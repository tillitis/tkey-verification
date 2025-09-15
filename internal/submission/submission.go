// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package submission

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tillitis/tkey-verification/internal/util"
	"sigsum.org/sigsum-go/pkg/requests"
)

type submissionJSON struct {
	Timestamp string `json:"timestamp"`
	AppTag    string `json:"apptag"`
	AppHash   string `json:"apphash"`
	Request   string `json:"request"`
}

type Submission struct {
	Timestamp time.Time
	AppTag    string
	AppHash   [sha512.Size]byte
	Request   requests.Leaf
}

func (s *Submission) FromJSON(b []byte) error {
	var sJ submissionJSON

	if err := json.Unmarshal(b, &sJ); err != nil {
		return fmt.Errorf("couldn't unmarshal JSON: %w", err)
	}

	var err error

	s.Timestamp, err = time.Parse(time.RFC3339, sJ.Timestamp)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	if sJ.AppTag == "" {
		return errors.New("app-tag empty")
	}
	s.AppTag = sJ.AppTag

	if err = util.DecodeHex(s.AppHash[:], sJ.AppHash); err != nil {
		return errors.New("couldn't decode app digest")
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

func (s *Submission) ToJSON() ([]byte, error) {
	var sJ submissionJSON

	sJ.Timestamp = s.Timestamp.UTC().Format(time.RFC3339)
	sJ.AppTag = s.AppTag
	sJ.AppHash = hex.EncodeToString(s.AppHash[:])

	reqTextBuilder := strings.Builder{}
	err := s.Request.ToASCII(&reqTextBuilder)
	if err != nil {
		return nil, fmt.Errorf("couldn't convert request to ASCII: %w", err)
	}
	sJ.Request = reqTextBuilder.String()

	json, err := json.Marshal(sJ)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal JSON: %w", err)
	}

	return json, nil
}

func (s *Submission) FromFile(fn string) error {
	submissionJSON, err := os.ReadFile(fn)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	return s.FromJSON(submissionJSON)
}

func (s *Submission) ToFile(fn string) error {
	sJ, err := s.ToJSON()
	if err != nil {
		return err
	}

	err = os.WriteFile(fn, append(sJ, '\n'), 0o600)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}
