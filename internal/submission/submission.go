package submission

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"sigsum.org/sigsum-go/pkg/requests"
)

type SubmissionJSON struct {
	Timestamp string `json:"timestamp"`
	AppTag    string `json:"apptag"`
	AppHash   string `json:"apphash"`
	Request   string `json:"request"`
}

type Submission struct {
	Timestamp time.Time
	AppTag    string
	AppHash   []byte
	Request   requests.Leaf
}

func (s *Submission) FromJson(b []byte) error {
	var sJ SubmissionJSON

	if err := json.Unmarshal(b, &sJ); err != nil {
		return fmt.Errorf("couldn't unmarshal JSON: %w", err)
	}

	var err error

	s.Timestamp, err = time.Parse(time.RFC3339, sJ.Timestamp)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	if sJ.AppTag == "" {
		return fmt.Errorf("app-tag empty")
	}
	s.AppTag = sJ.AppTag

	s.AppHash, err = hex.DecodeString(sJ.AppHash)
	if err != nil {
		return fmt.Errorf("couldn't decode app digest")
	}

	err = s.Request.FromASCII(bytes.NewBufferString(sJ.Request))
	if err != nil {
		return fmt.Errorf("couldn't decode request: %w", err)
	}

	_, err = s.Request.Verify()
	if err != nil {
		return fmt.Errorf("invalid request: %w", err)
	}

	return nil
}

func (s *Submission) FromFile(fn string) error {
	submissionJSON, err := os.ReadFile(fn)
	if err != nil {
		return err
	}

	return s.FromJson(submissionJSON)
}
