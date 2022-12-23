// Copyright (C) 2022 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

const (
	fnPriv = "signing.priv"
	fnPub  = "signing.pub"
)

func main() {
	fmt.Printf("NOTE this is a temporary tool\n")

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Printf("GenerateKey: %s", err)
		os.Exit(1)
	}
	privSeed := priv.Seed()

	if _, err = os.Stat(fnPriv); err == nil || !errors.Is(err, os.ErrNotExist) {
		fmt.Printf("%s already exists?\n", fnPriv)
		os.Exit(1)
	}
	if _, err = os.Stat(fnPub); err == nil || !errors.Is(err, os.ErrNotExist) {
		fmt.Printf("%s already exists?\n", fnPub)
		os.Exit(1)
	}

	err = os.WriteFile(fnPub, []byte(hex.EncodeToString(pub)+"\n"), 0o600)
	if err != nil {
		fmt.Printf("WriteFile: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Wrote %s\n", fnPub)

	err = os.WriteFile(fnPriv, []byte(hex.EncodeToString(privSeed)+"\n"), 0o600)
	if err != nil {
		fmt.Printf("WriteFile: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Wrote %s\n", fnPriv)
}
