package main

// func showFirmware(appBin *AppBin, devPath string, verbose bool) {
// 	le.Printf("Loading device app built from %s ...\n", appBin.String())
// 	udi, pubKey, ok := tkey.LoadSigner(appBin.Bin, devPath, verbose)
// 	if !ok {
// 		os.Exit(1)
// 	}
// 	le.Printf("TKey UDI: %s\n", udi.String())

// 	fw, err := verifyFirmwareHash(devPath, pubKey, udi)
// 	fmt.Printf("size: %v, hash: %v\n", fw.Size, fw.Hash)
// 	if err != nil {
// 		le.Printf("verifyFirmwareHash failed: %s\n", err)
// 		os.Exit(1)
// 	}
// 	le.Printf("TKey firmware with size:%d and verified hash:%0x…\n", fw.Size, fw.Hash[:16])

// 	// Locally generate a challenge and sign it
// 	challenge := make([]byte, 32)
// 	if _, err = rand.Read(challenge); err != nil {
// 		le.Printf("rand.Read failed: %s\n", err)
// 		os.Exit(1)
// 	}

// 	signature, err := tkey.Sign(devPath, pubKey, challenge)
// 	if err != nil {
// 		le.Printf("tkey.Sign failed: %s", err)
// 		os.Exit(1)
// 	}

// 	// Verify the signature against the extracted public key
// 	if !ed25519.Verify(pubKey, challenge, signature) {
// 		le.Printf("device signature failed verification!")
// 		os.Exit(1)
// 	}

// 	fmt.Printf("TKey has proved that it has the corresponding private key.\n")
// }
