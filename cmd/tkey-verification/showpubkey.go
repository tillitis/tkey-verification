// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tillitis/tkey-verification/internal/ssh"
	"github.com/tillitis/tkey-verification/internal/tkey"
)

func showPubkey(binPath string, dev Device, verbose bool) error {
	tk, err := tkey.NewTKey(dev.Path, dev.Speed, verbose)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	defer tk.Close()

	content, err := os.ReadFile(binPath)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	appHash := sha512.Sum512(content)

	pubKey, err := tk.LoadSigner(content)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	tag := strings.TrimSuffix(filepath.Base(binPath), ".bin")

	le.Printf("Public Key, app tag, and app hash for embedded vendor pubkeys follows on stdout:\n")
	fmt.Printf("%s %s %s\n", hex.EncodeToString(pubKey), tag, hex.EncodeToString(appHash[:]))

	var sshPubKey [ed25519.PublicKeySize]byte

	copy(sshPubKey[:], pubKey)
	fmt.Printf("SSH version: %v\n", ssh.FormatPublicEd25519(sshPubKey))

	return nil
}
