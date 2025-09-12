// SPDX-FileCopyrightText: 2025 Glasklar Teknik <glasklarteknik.se>
// SPDX-License-Identifier: BSD-2-Clause

package ssh

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
)

type (
	PublicKey     [ed25519.PublicKeySize]byte
	bytesOrString interface{ []byte | string }
)

func serializeUint32(x uint32) []byte {
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, x)
	return buffer
}

func serializeString[T bytesOrString](s T) []byte {
	if len(s) > math.MaxInt32 {
		log.Panicf("string too large for ssh, length %d", len(s))
	}
	buffer := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(buffer, uint32(len(s)))
	copy(buffer[4:], s)
	return buffer
}

// Skips prefix, if present, otherwise return nil.
func skipPrefix(buffer []byte, prefix []byte) []byte {
	if !bytes.HasPrefix(buffer, prefix) {
		return nil
	}
	return buffer[len(prefix):]
}

func serializePublicEd25519(pub *PublicKey) []byte {
	return bytes.Join([][]byte{
		serializeString("ssh-ed25519"),
		serializeString(pub[:])},
		nil)
}

func parsePublicEd25519(blob []byte) (PublicKey, error) {
	pub := skipPrefix(blob, bytes.Join([][]byte{
		serializeString("ssh-ed25519"),
		serializeUint32(crypto.PublicKeySize),
	}, nil))

	if pub == nil {
		return PublicKey{}, errors.New("invalid public key blob prefix")
	}
	if len(pub) != crypto.PublicKeySize {
		return PublicKey{}, fmt.Errorf("invalid public key length: %v", len(blob))
	}
	var ret PublicKey
	copy(ret[:], pub)
	return ret, nil
}

func ParsePublicEd25519(asciiKey string) (PublicKey, error) {
	// Split into fields, recognizing exclusively ascii space and TAB
	fields := strings.FieldsFunc(asciiKey, func(c rune) bool {
		return c == ' ' || c == '\t'
	})
	if len(fields) < 2 {
		return PublicKey{}, errors.New("invalid public key, splitting line failed")
	}
	if fields[0] != "ssh-ed25519" {
		return PublicKey{}, fmt.Errorf("unsupported public key type: %v", fields[0])
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return PublicKey{}, fmt.Errorf("%w", err)
	}
	return parsePublicEd25519(blob)
}

func FormatPublicEd25519(pub *PublicKey) string {
	return "ssh-ed25519 " +
		base64.StdEncoding.EncodeToString(serializePublicEd25519(pub)) +
		" sigsum key\n"
}
