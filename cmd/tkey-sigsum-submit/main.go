// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"strings"

	"github.com/spf13/pflag"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/submit"
)

var le = log.New(os.Stderr, "", 0)

type Submission struct {
	Timestamp string `json:"timestamp"`
	AppTag    string `json:"apptag"`
	AppHash   string `json:"apphash"`
	Request   string `json:"request"`
}

type Verification struct {
	Timestamp string `json:"timestamp"`
	AppTag    string `json:"apptag"`
	AppHash   string `json:"apphash"`
	Signature string `json:"signature,omitempty"`
	Proof     string `json:"proof"`
}

const policyText = `log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye

witness testwitness 5c35281928e9da396beede5f22a2251a589e6ac6de52a4de85de8634ffccaf6d

group  demo-quorum-rule all testwitness

quorum demo-quorum-rule
`

func main() {
	var verificationsDir, submissionsDir string
	var helpOnly bool

	// TODO: Add version command

	pflag.CommandLine.SetOutput(os.Stderr)
	pflag.CommandLine.SortFlags = false
	pflag.StringVarP(&submissionsDir, "submissions-dir", "m", "",
		"Read and log submission data from each file in `DIRECTORY`")
	pflag.StringVarP(&verificationsDir, "verifications-dir", "d", "",
		"Write verification data to a file located in `DIRECTORY` with the same name as the submission file")
	pflag.BoolVar(&helpOnly, "help", false, "Output this help.")
	pflag.Parse()

	if helpOnly {
		pflag.Usage()
		os.Exit(0)
	}

	if verificationsDir == "" || submissionsDir == "" {
		le.Printf("Missing arguments: -d, -m\n\n")
		pflag.Usage()
		os.Exit(1)
	}

	pol, err := policy.ParseConfig(bytes.NewBufferString(policyText))
	if err != nil {
		le.Fatalf("Failed to read sigsum policy: %v", err)
	}

	submitConfig := submit.Config{}
	submitConfig.Policy = pol

	entries, err := os.ReadDir(submissionsDir)
	if err != nil {
		le.Fatalf("Failed to read directory '%s': %v", submissionsDir, err)
	}

	for _, entry := range entries {
		err = processSubmissionFile(
			entry.Name(),
			submissionsDir,
			verificationsDir,
			submitConfig,
		)
		if err != nil {
			le.Fatalf("Failed to process submission file: %v", err)
		}
	}
}

func processSubmissionFile(fn, submDir, verDir string, submitConfig submit.Config) error {
	submissionPath := path.Join(submDir, fn)
	verificationPath := path.Join(verDir, fn)

	// TODO: Check if verification file already exists

	submission, err := submissionFromFile(submissionPath)
	if err != nil {
		return fmt.Errorf("Failed to open submission file: %w", err)
	}

	var req requests.Leaf
	err = req.FromASCII(bytes.NewBufferString(submission.Request))
	if err != nil {
		return fmt.Errorf("Failed to parse sigsum request: %w", err)
	}

	proofText, err := logDevice(req, submitConfig)
	if err != nil {
		return fmt.Errorf("Failed to log device: %w", err)
	}

	le.Printf("Got proof: \n%v\n", proofText)

	verification := Verification{
		Timestamp: submission.Timestamp,
		AppTag:    submission.AppTag,
		AppHash:   submission.AppHash,
		Proof:     proofText,
	}
	err = storeVerification(verificationPath, verification)
	if err != nil {
		return fmt.Errorf("Failed to store verification file: %w", err)
	}

	// TODO: Move or delete submission-file

	return nil
}

func submissionFromFile(fn string) (Submission, error) {
	var submission Submission

	le.Printf("Reading submission data from file %s ...\n", fn)
	submissionJSON, err := os.ReadFile(fn)
	if err != nil {
		return submission, fmt.Errorf("Failed to read submission file: %w", err)
	}

	if err = json.Unmarshal(submissionJSON, &submission); err != nil {
		return submission, fmt.Errorf("Failed to parse submission file: %w", err)
	}

	return submission, nil
}

func storeVerification(fn string, verification Verification) error {
	verificationJSON, err := json.Marshal(verification)
	if err != nil {
		return fmt.Errorf("JSON Marshal failed: %w", err)
	}

	err = os.WriteFile(fn, append(verificationJSON, '\n'), 0o644)
	if err != nil {
		return fmt.Errorf("WriteFile %s failed: %w", fn, err)
	}

	le.Printf("Verification file stored as '%s'", fn)

	return nil
}

func logDevice(req requests.Leaf, submitConfig submit.Config) (string, error) {
	ctx := context.Background()
	reqs := []requests.Leaf{req}

	proofs, err := submit.SubmitLeafRequests(ctx, &submitConfig, reqs)
	if err != nil {
		return "", fmt.Errorf("Failed to submit sigsum log request: %w", err)
	}
	if len(proofs) != 1 {
		return "", fmt.Errorf("Expected one proof from log, got %d", len(proofs))
	}

	proof := proofs[0]
	proofTextBuilder := strings.Builder{}

	err = proof.ToASCII(&proofTextBuilder)
	if err != nil {
		return "", fmt.Errorf("Failed to convert proof to ASCII: %w", err)
	}

	proofText := proofTextBuilder.String()

	return proofText, nil
}
