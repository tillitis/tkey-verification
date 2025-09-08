// SPDX-FileCopyrightText: 2023 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package appbins

import (
	"crypto/sha512"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/tillitis/tkey-verification/internal/util"
)

type AppBin struct {
	Tag string // Name and tag of device app
	Bin []byte // Actual binary of device app
}

func (a *AppBin) String() string {
	return fmt.Sprintf("tag:%s hash:%0x…", a.Tag, a.Hash())
}

func (a *AppBin) Hash() [sha512.Size]byte {
	return sha512.Sum512(a.Bin)
}

type AppBins struct {
	Bins map[[sha512.Size]byte]AppBin
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
		Bins: map[[sha512.Size]byte]AppBin{},
	}

	entries, err := binsFS.ReadDir(binsDir)
	if err != nil {
		return appBins, fmt.Errorf("error when reading %v: %w", binsDir, err)
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
			return appBins, fmt.Errorf("couldn't stat %v: %w", binFn, err)
		} else if info.Size() == 0 {
			return appBins, fmt.Errorf("missing file %v", binFn)
		}

		var bin []byte
		if bin, err = binsFS.ReadFile(path.Join(binsDir, binFn)); err != nil {
			return appBins, fmt.Errorf("couldn't read %v: %w", binFn, err)
		}

		// Require accompanying sha512 file with matching hash
		hashFn := binFn + ".sha512"
		var hashHex []byte
		if hashHex, err = binsFS.ReadFile(path.Join(binsDir, hashFn)); err != nil {
			return appBins, fmt.Errorf("couldn't read %v: %w", path.Join(binsDir, hashFn), err)
		}

		var hash [sha512.Size]byte

		if err := util.DecodeHex(hash[:], string(hashHex[:sha512.Size*2])); err != nil {
			return appBins, err
		}

		appBin := AppBin{
			Tag: tag,
			Bin: bin,
		}

		if appBin.Hash() != hash {
			return appBins, fmt.Errorf("digests of %v != %v", binFn, hashFn)
		}

		appBins.Bins[hash] = appBin
	}

	return appBins, nil
}

func MustAppBins() AppBins {
	bins, err := NewAppBins()
	if err != nil {
		panic(err)
	}

	return bins
}
