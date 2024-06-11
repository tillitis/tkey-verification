// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

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
	Tag string
	Bin []byte
}

func (a *AppBin) String() string {
	return fmt.Sprintf("tag:%s hash:%0x…", a.Tag, a.Hash()[:16])
}

func (a *AppBin) Hash() []byte {
	hash := sha512.Sum512(a.Bin)
	return hash[:]
}

type AppBins struct {
	Bins   map[string]AppBin
	latest string
}

// Only used by show-pubkey cmd
func (a AppBins) GetByTagOnly(tag string) (AppBin, error) {
	for _, appBin := range a.Bins {
		if appBin.Tag == tag {
			return appBin, nil
		}
	}
	return AppBin{}, fmt.Errorf("app binary missing for tag:%s", tag)
}

func (a AppBins) Get(hash string) (AppBin, error) {
	if val, ok := a.Bins[hash]; ok {
		return val, nil
	}

	return AppBin{}, fmt.Errorf("not found")
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

func (a AppBins) Latest() AppBin {
	return a.Bins[a.latest]
}

func NewAppBins(latestHash string) (AppBins, error) {
	var appBins = AppBins{
		Bins: map[string]AppBin{},
	}

	entries, err := binsFS.ReadDir(binsDir)
	if err != nil {
		return AppBins{}, fmt.Errorf("ReadDir failed: %w", err)
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
			return AppBins{}, fmt.Errorf("Info on %s failed: %w", binFn, err)
		} else if info.Size() == 0 {
			return AppBins{}, fmt.Errorf("File %s is empty", binFn)
		}

		var bin []byte
		if bin, err = binsFS.ReadFile(path.Join(binsDir, binFn)); err != nil {
			return AppBins{}, fmt.Errorf("ReadFile failed: %w", err)
		}

		// Require accompanying sha512 file with matching hash
		hashFn := binFn + ".sha512"
		var hash []byte
		if hash, err = binsFS.ReadFile(path.Join(binsDir, hashFn)); err != nil {
			return AppBins{}, fmt.Errorf("ReadFile failed: %w", err)
		}
		if hash, err = hex.DecodeString(string(hash[:sha512.Size*2])); err != nil {
			return AppBins{}, fmt.Errorf("decode hex in file %s failed: %w", hashFn, err)
		}

		appBin := AppBin{
			Tag: tag,
			Bin: bin,
		}

		if !bytes.Equal(appBin.Hash(), hash) {
			return AppBins{}, fmt.Errorf("Hash of %s does not match hash in %s", binFn, hashFn)
		}

		appBins.Bins[hex.EncodeToString(hash)] = appBin
	}

	if _, ok := appBins.Bins[latestHash]; ok {
		appBins.latest = latestHash
	} else {
		return AppBins{}, fmt.Errorf("Requested latest hash binary not found: %v", latestHash)
	}

	return appBins, nil
}
