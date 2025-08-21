package verification

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
	//	"github.com/tillitis/tkey-verification/internal/errors"
)

type Verification struct {
	Timestamp string `json:"timestamp"`
	AppTag    string `json:"apptag"`
	AppHash   string `json:"apphash"`
	Signature string `json:"signature"`
	Proof     string `json:"proof"`
}

func (v *Verification) FromJson(b []byte) error {
	if err := json.Unmarshal(b, &v); err != nil {
		return fmt.Errorf("couldn't unmarshal JSON: %w", err)
	}

	return nil
}

func (v *Verification) FromFile(fn string) error {
	verificationJSON, err := os.ReadFile(fn)
	if err != nil {
		return err
	}

	if err = json.Unmarshal(verificationJSON, &v); err != nil {
		return fmt.Errorf("couldn't unmarshal JSON: %w", err)
	}

	return nil
}

func (verification *Verification) FromURL(verifyURL string) error {
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

	if err = json.Unmarshal(verificationJSON, &verification); err != nil {
		return fmt.Errorf("couldn't unmarshal JSON: %w", err)
	}

	return nil
}
