// Copyright (C) 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package appbins

import (
	"embed"
	"fmt"
	"log"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
)

var le = log.New(os.Stderr, "", 0)

func Tags() []string {
	if err := initAppBins(); err != nil {
		le.Printf("Failed to init embedded signer-apps: %s\n", err)
		os.Exit(1)
	}

	var tags []string
	for _, appBin := range *appBins {
		tags = append(tags, appBin.Tag)
	}

	sort.Strings(tags)

	return tags
}

func Get(tag string) (*AppBin, error) {
	if err := initAppBins(); err != nil {
		le.Printf("Failed to init embedded signer-apps: %s\n", err)
		os.Exit(1)
	}

	for i, appBin := range *appBins {
		if appBin.Tag == tag {
			return &(*appBins)[i], nil
		}
	}
	return nil, fmt.Errorf("embedded signer-app binary for tag \"%s\" is missing", tag)
}

var (
	appBins *[]AppBin
	lock    = &sync.Mutex{}
)

//go:embed bins/*.bin
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

	for _, entry := range entries {
		fn := entry.Name()
		if !entry.Type().IsRegular() || !strings.HasSuffix(fn, ".bin") {
			continue
		}
		tag := strings.TrimSuffix(fn, ".bin")
		if tag == "" {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("Info on %s failed: %w", fn, err)
		}
		if info.Size() == 0 {
			return fmt.Errorf("File %s is empty", fn)
		}

		bin, err := binsFS.ReadFile(path.Join(binsDir, fn))
		if err != nil {
			return fmt.Errorf("ReadFile failed: %w", err)
		}

		newAppBins = append(newAppBins, AppBin{
			Tag: tag,
			Bin: bin,
		})
	}

	appBins = &newAppBins
	return nil
}

type AppBin struct {
	Tag string
	Bin []byte
}
