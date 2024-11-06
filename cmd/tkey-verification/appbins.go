// Copyright (C) 2023-2024 - Tillitis AB
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
		return AppBins{}, IOError{path: binsDir, err: err}
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
			return AppBins{}, IOError{path: binFn, err: err}
		} else if info.Size() == 0 {
			return AppBins{}, MissingError{what: binFn}
		}

		var bin []byte
		if bin, err = binsFS.ReadFile(path.Join(binsDir, binFn)); err != nil {
			return AppBins{}, IOError{path: binFn, err: err}
		}

		// Require accompanying sha512 file with matching hash
		hashFn := binFn + ".sha512"
		var hash []byte
		if hash, err = binsFS.ReadFile(path.Join(binsDir, hashFn)); err != nil {
			return AppBins{}, IOError{path: binFn, err: err}
		}
		if hash, err = hex.DecodeString(string(hash[:sha512.Size*2])); err != nil {
			return AppBins{}, IOError{path: hashFn, err: err}
		}

		appBin := AppBin{
			Tag: tag,
			Bin: bin,
		}

		if !bytes.Equal(appBin.Hash(), hash) {
			return AppBins{}, EqualError{one: binFn, two: hashFn}
		}

		appBins.Bins[hex.EncodeToString(hash)] = appBin
	}

	return appBins, nil
}
