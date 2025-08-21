// SPDX-FileCopyrightText: 2023 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bytes"
	"crypto/sha512"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

type AppBin struct {
	Tag string // Name and tag of device app
	Bin []byte // Actual binary of device app
}

func (a *AppBin) String() string {
	return fmt.Sprintf("tag:%s hash:%0x…", a.Tag, a.Hash()[:16])
}

func (a *AppBin) Hash() []byte {
	hash := sha512.Sum512(a.Bin)
	return hash[:]
}

type AppBins struct {
	Bins map[string]AppBin
}

// Get returns an AppBin indexed by the app hash digest.
func (a AppBins) Get(hash string) (AppBin, error) {
	if val, ok := a.Bins[hash]; ok {
		return val, nil
	}

	return AppBin{}, ErrNotFound
}

//go:embed bins/*.bin bins/*.bin.sha512
var binsFS embed.FS

const binsDir = "bins"

func (a AppBins) Tags() []string {
	tags := []string{}

	for _, appBin := range a.Bins {
		tags = append(tags, appBin.Tag)
	}

	sort.Strings(tags)

	return tags
}

// NewAppBins initializes the embedded device apps.
func NewAppBins() (AppBins, error) {
	var appBins = AppBins{
		Bins: map[string]AppBin{},
	}

	entries, err := binsFS.ReadDir(binsDir)
	if err != nil {
		return AppBins{}, fmt.Errorf("error when reading %v: %w", err)
	}

	for _, entry := range entries {
		binFn := entry.Name()
		if !entry.Type().IsRegular() || !strings.HasSuffix(binFn, ".bin") {
			continue
		}

		tag := strings.TrimSuffix(binFn, ".bin")

		if tag == "" {
			continue
		}

		var info fs.FileInfo

		if info, err = entry.Info(); err != nil {
			return AppBins{}, fmt.Errorf("couldn't stat %v: %w", binFn, err)
		} else if info.Size() == 0 {
			return AppBins{}, fmt.Errorf("missing file %v", binFn)
		}

		var bin []byte
		if bin, err = binsFS.ReadFile(path.Join(binsDir, binFn)); err != nil {
			return AppBins{}, fmt.Errorf("couldn't read %v: %w", binFn, err)
		}

		// Require accompanying sha512 file with matching hash
		hashFn := binFn + ".sha512"
		var hash []byte
		if hash, err = binsFS.ReadFile(path.Join(binsDir, hashFn)); err != nil {
			return AppBins{}, fmt.Errorf("couldn't read %v: %w", path.Join(binsDir, hashFn), err)
		}
		if hash, err = hex.DecodeString(string(hash[:sha512.Size*2])); err != nil {
			return AppBins{}, err
		}

		appBin := AppBin{
			Tag: tag,
			Bin: bin,
		}

		if !bytes.Equal(appBin.Hash(), hash) {
			return AppBins{}, fmt.Errorf("digests of %v != %v", binFn, hashFn)
		}

		appBins.Bins[hex.EncodeToString(hash)] = appBin
	}

	return appBins, nil
}
