// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package appbins

import (
	"bytes"
	"crypto/sha512"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var (
	// Appbin names (without .bin suffix) to ignore when embedding.
	// Useful when needed to tag verisigner versions during
	// development (and wanted tag names that follow the "live"
	// pattern). Note that we currently duplicate this in the build
	// script ../../build-appbins-from-tags.sh
	ignoreBins = []string{"verisigner-v0.0.1", "verisigner-v0.0.2"}

	// For filtering tags when picking device signing appbin:
	prefix = "verisigner"
	tagRE  = regexp.MustCompile(fmt.Sprintf(`^%s-v([0-9]+)\.([0-9]+)\.([0-9]+)$`, prefix))
)

var le = log.New(os.Stderr, "", 0)

// GetDeviceSigner returns the AppBin to run on the "device under
// verification", i.e. when using the command "remote-sign". The tag
// and hash of this AppBin then ends up in the verification data and
// later used by the command "verify".
func GetDeviceSigner() (*AppBin, error) {
	if err := initAppBins(); err != nil {
		return nil, fmt.Errorf("Failed to init embedded verisigner-apps: %w", err)
	}

	if deviceSignAppBin == nil {
		return nil, fmt.Errorf("deviceSignAppBin == nil")
	}

	return deviceSignAppBin, nil
}

func Get(tag string, hash []byte) (*AppBin, error) {
	if err := initAppBins(); err != nil {
		return nil, fmt.Errorf("Failed to init embedded verisigner-apps: %w", err)
	}

	for i, appBin := range appBins {
		if appBin.Tag == tag {
			if !bytes.Equal(appBin.Hash(), hash) {
				return nil, fmt.Errorf("app binary with %s exists, but hash:%0x… was requested", appBin.String(), hash[:16])
			}
			return &appBins[i], nil
		}
	}
	return nil, fmt.Errorf("app binary missing for tag:%s", tag)
}

func Tags() []string {
	if err := initAppBins(); err != nil {
		le.Printf("Failed to init embedded verisigner-apps: %s\n", err)
		os.Exit(1)
	}

	var tags []string
	for _, appBin := range appBins {
		tags = append(tags, appBin.Tag)
	}

	sort.Strings(tags)
	return tags
}

// Only used by show-pubkey cmd
func GetByTagOnly(tag string) (*AppBin, error) {
	if err := initAppBins(); err != nil {
		return nil, fmt.Errorf("Failed to init embedded verisigner-apps: %w", err)
	}

	for i, appBin := range appBins {
		if appBin.Tag == tag {
			return &appBins[i], nil
		}
	}
	return nil, fmt.Errorf("app binary missing for tag:%s", tag)
}

var (
	appBins          []AppBin
	deviceSignAppBin *AppBin
	lock             = &sync.Mutex{}
)

// nolint:typecheck // Avoid lint error when the embedding file is missing.
//
//go:embed bins/*.bin bins/*.bin.sha512
var binsFS embed.FS

const binsDir = "bins"

func initAppBins() error {
	lock.Lock()
	defer lock.Unlock()

	if appBins != nil {
		return nil
	}

	entries, err := binsFS.ReadDir(binsDir)
	if err != nil {
		return fmt.Errorf("ReadDir failed: %w", err)
	}

	var newAppBins []AppBin

processEntries:
	for _, entry := range entries {
		binFn := entry.Name()
		if !entry.Type().IsRegular() || !strings.HasSuffix(binFn, ".bin") {
			continue
		}
		tag := strings.TrimSuffix(binFn, ".bin")
		if tag == "" {
			continue
		}
		for _, ignore := range ignoreBins {
			if tag == ignore {
				continue processEntries
			}
		}

		var info fs.FileInfo
		if info, err = entry.Info(); err != nil {
			return fmt.Errorf("Info on %s failed: %w", binFn, err)
		} else if info.Size() == 0 {
			return fmt.Errorf("File %s is empty", binFn)
		}

		var bin []byte
		if bin, err = binsFS.ReadFile(path.Join(binsDir, binFn)); err != nil {
			return fmt.Errorf("ReadFile failed: %w", err)
		}

		// Require accompanying sha512 file with matching hash
		hashFn := binFn + ".sha512"
		var hash []byte
		if hash, err = binsFS.ReadFile(path.Join(binsDir, hashFn)); err != nil {
			return fmt.Errorf("ReadFile failed: %w", err)
		}
		if hash, err = hex.DecodeString(string(hash[:sha512.Size*2])); err != nil {
			return fmt.Errorf("decode hex in file %s failed: %w", hashFn, err)
		}

		appBin := AppBin{
			Tag: tag,
			Bin: bin,
		}

		if !bytes.Equal(appBin.Hash(), hash) {
			return fmt.Errorf("Hash of %s does not match hash in %s", binFn, hashFn)
		}

		newAppBins = append(newAppBins, appBin)
	}

	// Check that all .bin.sha512-files have accompanying .bin-file
checkEntries:
	for _, entry := range entries {
		fn := entry.Name()
		if !entry.Type().IsRegular() || !strings.HasSuffix(fn, ".bin.sha512") {
			continue
		}
		tag := strings.TrimSuffix(fn, ".bin.sha512")
		if tag == "" {
			continue
		}
		for _, ignore := range ignoreBins {
			if tag == ignore {
				continue checkEntries
			}
		}

		found := false
		for _, appBin := range newAppBins {
			if appBin.Tag == tag {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("Found hash file %s without any corresponding .bin-file", fn)
		}
	}

	latest, err := pickLatest(newAppBins)
	if err != nil {
		return fmt.Errorf("Could not pick the verisigner-app for device signing: %w", err)
	}

	appBins = newAppBins
	deviceSignAppBin = latest

	return nil
}

func pickLatest(bins []AppBin) (*AppBin, error) {
	var latest *AppBin
	latestVer := make([]int64, 3)

	var tags []string
	for i := range bins {
		tags = append(tags, bins[i].Tag)
		matches := tagRE.FindStringSubmatch(bins[i].Tag)
		if matches == nil {
			continue
		}
		if len(matches) != 1+3 {
			// can't happen, right?
			return nil, fmt.Errorf("unexpected matching: %v", matches)
		}

		// only deal with the submatches
		matches = matches[1:]

		ver, err := stringsToInts(matches)
		if err != nil {
			return nil, err
		}

		if latest == nil || less(latestVer, ver) {
			latest = &bins[i]
			latestVer = ver
		}
	}

	if latest == nil {
		return nil, fmt.Errorf("found no app binary with tag matching `%s` candidates: %v",
			tagRE.String(), tags)
	}
	return latest, nil
}

func stringsToInts(numbers []string) ([]int64, error) {
	ints := make([]int64, len(numbers))
	for i, num := range numbers {
		v, err := strconv.ParseInt(num, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}
		ints[i] = v
	}
	return ints, nil
}

func less(i []int64, j []int64) bool {
	if len(i) != 3 || len(j) != 3 {
		// won't happen given how we currently use this func
		panic("less func got len(slice) != 3")
	}
	for n := 0; n < 3; n++ {
		if i[n] < j[n] {
			return true
		} else if i[n] > j[n] {
			return false
		}
	}
	return false
}

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
