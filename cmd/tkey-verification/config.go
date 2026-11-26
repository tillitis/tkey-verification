// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"os"

	"github.com/tillitis/tkey-verification/internal/appbins"
	"github.com/tillitis/tkey-verification/internal/firmware"
	"github.com/tillitis/tkey-verification/internal/sigsum"
	"github.com/tillitis/tkey-verification/internal/util"
	"gopkg.in/yaml.v2"
)

type FileConf struct {
	AuthAppDigest string `yaml:"authappdigest"` // Digest of app for device authentication
	ActiveKey     string `yaml:"activekey"`     // Submission public key - needs to be in data.go, too.
	ActiveSerial  string `yaml:"activeserial"`  // Serial number of submission TKey
}

type Conf struct {
	AuthAppBin   appbins.AppBin     // App used for device authentication
	SubmitKey    *sigsum.PubKey     // Submission public key
	ActiveSerial string             // Serial number of submission TKey
	Firmwares    firmware.Firmwares // All the known firmwares
}

func loadConfig(fn string) (Conf, error) {
	var fileConf FileConf
	var conf Conf

	rawConfig, err := os.ReadFile(fn)
	if err != nil {
		return conf, fmt.Errorf("couldn't read config file: %w", err)
	}

	err = yaml.Unmarshal(rawConfig, &fileConf)
	if err != nil {
		return conf, fmt.Errorf("parse error in config file: %w", err)
	}

	// Find the app to use
	var appHash [sha512.Size]byte

	if err = util.DecodeHex(appHash[:], fileConf.AuthAppDigest); err != nil {
		return conf, fmt.Errorf("couldn't decode authappdigest: %w", err)
	}

	appBin, ok := appbins.MustAppBins().Bins[appHash]
	if !ok {
		return conf, fmt.Errorf("configured authappdigest not found: %v", fileConf.AuthAppDigest)
	}

	conf.AuthAppBin = appBin

	// Get our submission public key which also contains
	// information about what device app to run on signing device.
	submitKey, err := findSubmitKey(fileConf.ActiveKey)
	if err != nil {
		return conf, fmt.Errorf("%w", err)
	}

	conf.SubmitKey = submitKey

	if fileConf.ActiveSerial == "" {
		return conf, errors.New("empty activeserial")
	}

	conf.ActiveSerial = fileConf.ActiveSerial

	// Get our firmwares. Needed to be able find the authenticating TKey
	// device's firmware and verify that it's known.
	conf.Firmwares.MustDecodeEmbedded()

	return conf, nil
}

// findSubmitKey looks for a Sigsum tranparency log submit key
// identified by confActiveKey (in SSH public key format) in the
// embedded database of all used submit keys in internal/data.
//
// It returns the found key in binary form, if any, and any errors.
func findSubmitKey(confActiveKey string) (*sigsum.PubKey, error) {
	var log sigsum.Log

	log.MustDecodeEmbedded()

	// Check that the configured submit key is in the embedded
	// data for the Sigsum log and convert it into a usable form.
	submitKey, err := log.FindSSHKey(confActiveKey)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return submitKey, nil
}
