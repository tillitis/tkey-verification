// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tillitis/tkey-verification/internal/tkey"
)

func showPubkey(binPath string, dev Device, verbose bool) {
	tk, err := tkey.NewTKey(dev.Path, dev.Speed, verbose)
	if err != nil {
		le.Printf("Couldn't connect to TKey: %v\n", err)
		os.Exit(1)
	}

	exit := func(code int) {
		tk.Close()
		os.Exit(code)
	}

	content, err := os.ReadFile(binPath)
	if err != nil {
		le.Printf("ReadFile: %v", err)
		exit(1)
	}

	appHash := sha512.Sum512(content)

	pubKey, err := tk.LoadSigner(content)
	if err != nil {
		le.Printf("LoadSigner: %v\n", err)
		exit(1)
	}

	tag := strings.TrimSuffix(filepath.Base(binPath), ".bin")

	le.Printf("Public Key, app tag, and app hash for embedded vendor pubkeys follows on stdout:\n")
	fmt.Printf("%s %s %s\n", hex.EncodeToString(pubKey), tag, hex.EncodeToString(appHash[:]))

	exit(0)
}
