// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package submission

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/tillitis/tkey-verification/internal/util"
	sumcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/requests"
)

const submJSON = `
{
  "timestamp":"2025-09-02T10:56:48Z",
  "apptag":"signer-v1.0.1",
  "apphash":"cd3c4f433f84648428113bd0a0cc407b2150e925a51b478006321e5a903c1638ce807138d1cc1f8f03cfb6236a87de0febde3ce0ddf177208e5483d1c169bac4",
  "request":"message=f23e454ee9c9627dd1a80f6ab2e1565fa0cda3a7c91f853eb8099ff645674719\nsignature=b4f9eabdcb6b05d259e964ba6fa427c178b5586d30e6b4026287656c8a7ee2674af33d2c05701ea8f98458fe7c54b787c7a73c0fda6f09046bcf7604cea86c00\npublic_key=50d9a125f51d85ffa1fb12011bdae05d39e03cda2a35d0daf3077072daabbb10\n"
}
`

func TestJSONDecodeSubmission(t *testing.T) {
	var s Submission

	if err := s.FromJSON([]byte(submJSON)); err != nil {
		t.Fatal(err)
	}

	wantTime := time.Date(2025, 9, 2, 10, 56, 48, 0, time.UTC)
	if s.Timestamp != wantTime {
		t.Fatalf("Incorrect timestamp. Got: %v, want: %v", s.Timestamp, wantTime)
	}

	wantAppTag := "signer-v1.0.1"
	if s.AppTag != wantAppTag {
		t.Fatalf("Incorrect apptag. Got: %v, want: %v", s.AppTag, wantAppTag)
	}

	wantAppHash := mustDecodeHash("cd3c4f433f84648428113bd0a0cc407b2150e925a51b478006321e5a903c1638ce807138d1cc1f8f03cfb6236a87de0febde3ce0ddf177208e5483d1c169bac4")
	if s.AppHash != wantAppHash {
		t.Logf("Incorrect apphash. Got: %v, want: %v", s.AppHash, wantAppHash)
	}

	rMessage := mustDecodeHexString("f23e454ee9c9627dd1a80f6ab2e1565fa0cda3a7c91f853eb8099ff645674719")
	rSignature := mustDecodeHexString("b4f9eabdcb6b05d259e964ba6fa427c178b5586d30e6b4026287656c8a7ee2674af33d2c05701ea8f98458fe7c54b787c7a73c0fda6f09046bcf7604cea86c00")
	rPublicKey := mustDecodeHexString("50d9a125f51d85ffa1fb12011bdae05d39e03cda2a35d0daf3077072daabbb10")
	wantRequest := requests.Leaf{
		Message:   sumcrypto.Hash(rMessage),
		Signature: sumcrypto.Signature(rSignature),
		PublicKey: sumcrypto.PublicKey(rPublicKey),
	}
	if s.Request != wantRequest {
		t.Fatalf("Incorrect request. Got: %+v, want: %+v", s.Request, wantRequest)
	}

	_, err := s.Request.Verify()
	if err != nil {
		t.Fatal("Not a valid sigsum leaf request")
	}
}

func TestJSONEncodeSubmission(t *testing.T) {
	appHash := mustDecodeHash("cd3c4f433f84648428113bd0a0cc407b2150e925a51b478006321e5a903c1638ce807138d1cc1f8f03cfb6236a87de0febde3ce0ddf177208e5483d1c169bac4")
	rMessage := mustDecodeHexString("f23e454ee9c9627dd1a80f6ab2e1565fa0cda3a7c91f853eb8099ff645674719")
	rSignature := mustDecodeHexString("b4f9eabdcb6b05d259e964ba6fa427c178b5586d30e6b4026287656c8a7ee2674af33d2c05701ea8f98458fe7c54b787c7a73c0fda6f09046bcf7604cea86c00")
	rPublicKey := mustDecodeHexString("50d9a125f51d85ffa1fb12011bdae05d39e03cda2a35d0daf3077072daabbb10")
	s := Submission{
		Timestamp: time.Date(2025, 9, 2, 10, 56, 48, 0, time.UTC),
		AppTag:    "signer-v1.0.1",
		AppHash:   appHash,
		Request: requests.Leaf{
			Message:   sumcrypto.Hash(rMessage),
			Signature: sumcrypto.Signature(rSignature),
			PublicKey: sumcrypto.PublicKey(rPublicKey),
		},
	}

	wantJSONStr := submJSON
	wantJSONStr = strings.ReplaceAll(wantJSONStr, "\n", "")
	wantJSONStr = strings.ReplaceAll(wantJSONStr, " ", "")
	wantJSON := []byte(wantJSONStr)

	js, err := s.ToJSON()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(js, wantJSON) {
		t.Fatalf("Incorrect JSON. Got: %s, want: %s", js, wantJSON)
	}
}

func mustDecodeHexString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}

	return b
}

func mustDecodeHash(s string) [sha512.Size]byte {
	var hash [sha512.Size]byte

	if err := util.DecodeHex(hash[:], s); err != nil {
		panic(err)
	}

	return hash
}
