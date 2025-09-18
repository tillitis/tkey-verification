// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package sigsum

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/tillitis/tkey-verification/internal/appbins"
	"github.com/tillitis/tkey-verification/internal/data"
	"github.com/tillitis/tkey-verification/internal/util"
	sumcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/policy"
)

type PubKey struct {
	Name    string
	Key     [ed25519.PublicKeySize]byte // Vendor public key
	Tag     string                      // Name and tag of the device app
	AppHash [sha512.Size]byte           // Hash of app binary used for signing with this key
	AppBin  appbins.AppBin              // The actual device app binary
	Start   time.Time
	End     time.Time
}

func (p PubKey) String() string {
	return fmt.Sprintf("%v using app %v: %x\n  Valid: %v-%v\n", p.Name, p.Tag, p.Key, p.Start.Format(time.RFC3339), p.End.Format(time.RFC3339))
}

type Log struct {
	Keys       map[[ed25519.PublicKeySize]byte]PubKey // key -> PubKey
	SubmitKeys map[sumcrypto.Hash]sumcrypto.PublicKey
	Policy     *policy.Policy
}

type State int

const (
	sName = iota
	sKey
	sTag
	sAppHash
	sStart
	sEnd
)

func ParseKeys(r io.Reader, appBins appbins.AppBins) (map[[ed25519.PublicKeySize]byte]PubKey, error) {
	var pubkey PubKey
	var state State

	pubKeys := map[[ed25519.PublicKeySize]byte]PubKey{}

	state = sName
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments or empty lines
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		switch state {
		case sName:
			pubkey.Name = line
			state = sKey

		case sKey:
			pkey, err := key.ParsePublicKey(line)
			if err != nil {
				return nil, fmt.Errorf("%w", err)
			}

			pubkey.Key = pkey
			state = sTag

		case sTag:
			pubkey.Tag = line
			state = sAppHash

		case sAppHash:
			if err := util.DecodeHex(pubkey.AppHash[:], line); err != nil {
				return nil, fmt.Errorf("couldn't decode pubkey app hash: %w", err)
			}

			// Do we have the app?
			app, ok := appBins.Bins[pubkey.AppHash]
			if !ok {
				// App not found.
				return nil, errors.New("app used for key not found")
			}

			pubkey.AppBin = app

			state = sStart

		case sStart:
			startTime, err := time.Parse(time.RFC3339, line)
			if err != nil {
				return nil, fmt.Errorf("couldn't parse key start time: %w", err)
			}

			pubkey.Start = startTime
			state = sEnd

		case sEnd:
			endTime, err := time.Parse(time.RFC3339, line)
			if err != nil {
				return nil, fmt.Errorf("couldn't parse key end time: %w", err)
			}

			pubkey.End = endTime

			// This is the last, store away and reset state to begin again
			pubKeys[pubkey.Key] = pubkey

			state = sName
		default:
			return nil, errors.New("unknown state when parsing keys")
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to parse sigsum keys: %w", err)
	}

	return pubKeys, nil
}

func (s *Log) FromEmbedded() error {
	return s.FromString(data.SigsumConf, data.PolicyStr)
}

func (s *Log) FromString(sigsumConf string, policyStr string) error {
	// Get all our embedded device apps used for vendor signing
	appBins, err := appbins.NewAppBins()
	if err != nil {
		fmt.Printf("Failed to init embedded device apps: %v\n", err)
		os.Exit(1)
	}

	keys, err := ParseKeys(bytes.NewBufferString(sigsumConf), appBins)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	s.Keys = keys

	// Transform to Sigsum submitkeys
	s.SubmitKeys = make(map[sumcrypto.Hash]sumcrypto.PublicKey)
	for _, key := range keys {
		s.SubmitKeys[sumcrypto.HashBytes(key.Key[:])] = key.Key
	}

	// Parse policy
	s.Policy, err = policy.ParseConfig(bytes.NewBufferString(policyStr))
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}
