package verification

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/tillitis/tkey-verification/internal/vendorkey"
	sumcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/proof"
)

type VerificationType int

const (
	VerSig VerificationType = iota
	VerProof
)

type VerificationJson struct {
	Timestamp string `json:"timestamp"`
	AppTag    string `json:"apptag"`
	AppHash   string `json:"apphash"`
	Signature string `json:"signature"`
	Proof     string `json:"proof"`
}

type Verification struct {
	Type      VerificationType
	Timestamp time.Time
	AppTag    string
	AppHash   []byte
	Signature []byte
	Proof     proof.SigsumProof
}

func (v *Verification) FromJson(b []byte) error {
	var vJ VerificationJson

	if err := json.Unmarshal(b, &vJ); err != nil {
		return fmt.Errorf("couldn't unmarshal JSON: %w", err)
	}

	var err error

	v.Timestamp, err = time.Parse(time.RFC3339, vJ.Timestamp)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	if vJ.AppTag == "" {
		return fmt.Errorf("app-tag empty")
	}
	v.AppTag = vJ.AppTag

	v.AppHash, err = hex.DecodeString(vJ.AppHash)
	if err != nil {
		return fmt.Errorf("couldn't decode app digest")
	}

	if vJ.Proof != "" && vJ.Signature != "" {
		return fmt.Errorf("verification file contains both Sigsum proof and vendor signature")
	}

	if vJ.Proof != "" {
		// This contains a Sigsum proof
		v.Type = VerProof

		if err := v.Proof.FromASCII(bytes.NewBufferString(vJ.Proof)); err != nil {
			return fmt.Errorf("couldn't parse proof: %w", err)
		}
	} else {
		// Old type vendor signature
		v.Type = VerSig

		v.Signature, err = hex.DecodeString(vJ.Signature)
		if err != nil {
			return fmt.Errorf("couldn't decode vendor signature")
		}
	}

	return nil
}

func (v *Verification) FromFile(fn string) error {
	verificationJSON, err := os.ReadFile(fn)
	if err != nil {
		return err
	}

	return v.FromJson(verificationJSON)

	return nil
}

func (v *Verification) FromURL(verifyURL string) error {
	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(verifyURL) // #nosec G107
	if err != nil {
		return fmt.Errorf("error accessing %v: %v", verifyURL, resp.Status)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error accessing %v: %v", verifyURL, resp.Status)
	}

	verificationJSON, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("couldn't ready body: %w", err)
	}

	return v.FromJson(verificationJSON)

	return nil
}

func (v *Verification) IsProof() bool {
	return v.Type == VerProof
}

func (v *Verification) IsSig() bool {
	return v.Type == VerSig
}

// VerifySig verifies a signature (Signature in the struct) over
// message 'msg' against a number of public keys in 'vendorKeys'.
//
// It returns the matching public key that successfully verified the
// signature, if any, and any error.
func (v *Verification) VerifySig(msg []byte, vendorKeys vendorkey.VendorKeys) (vendorkey.PubKey, error) {
	// We allow for any of the known vendor keys and return on the
	// first which verifies.
	for _, vendorPubKey := range vendorKeys.Keys {
		if ed25519.Verify(vendorPubKey.PubKey[:], msg, v.Signature) {
			return vendorPubKey, nil
		}
	}

	return vendorkey.PubKey{}, fmt.Errorf("vendor signature not verified")
}

func (v *Verification) VerifyProof(msg []byte, policy policy.Policy, sigsumKeys map[sumcrypto.Hash]sumcrypto.PublicKey) error {
	digest := sumcrypto.HashBytes(msg)
	fmt.Printf("digest: %x\n", digest)

	if err := v.Proof.Verify(&digest, sigsumKeys, &policy); err != nil {
		return err
	}

	return nil
}
