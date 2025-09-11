// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path"

	"github.com/spf13/pflag"
	"github.com/tillitis/tkey-verification/internal/data"
	"github.com/tillitis/tkey-verification/internal/submission"
	"github.com/tillitis/tkey-verification/internal/util"
	"github.com/tillitis/tkey-verification/internal/verification"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/proof"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/submit"
)

const progname = "tkey-sigsum-submit"

var version string
var le = log.New(os.Stderr, "", 0)

func main() {
	var verificationsDir, submissionsDir, processedSubmissionsDir string
	var helpOnly, versionOnly bool

	pflag.CommandLine.SetOutput(os.Stderr)
	pflag.CommandLine.SortFlags = false
	pflag.StringVarP(&submissionsDir, "submissions-dir", "m", "",
		"Read and log submission data from each file in `DIRECTORY`")
	pflag.StringVarP(&processedSubmissionsDir, "processed-submissions-dir", "n", "",
		"Move submission data files to `DIRECTORY` after submission to log")
	pflag.StringVarP(&verificationsDir, "verifications-dir", "d", "",
		"Write verification data to a file located in `DIRECTORY` with the same name as the submission file")
	pflag.BoolVar(&helpOnly, "help", false, "Output this help.")
	pflag.BoolVar(&versionOnly, "version", false, "Output version information.")
	pflag.Parse()

	if helpOnly {
		pflag.Usage()
		os.Exit(0)
	}

	if versionOnly {
		fmt.Printf("%s %s\n", progname, util.Version(version))
		os.Exit(0)
	}

	if verificationsDir == "" || submissionsDir == "" || processedSubmissionsDir == "" {
		le.Printf("Missing arguments: -d, -m, -n\n\n")
		pflag.Usage()
		os.Exit(1)
	}

	pol, err := policy.ParseConfig(bytes.NewBufferString(data.PolicyStr))
	if err != nil {
		le.Fatalf("Failed to read sigsum policy: %v", err)
	}

	submitConfig := submit.Config{}
	submitConfig.Policy = pol

	err = processSubmissionDir(submissionsDir, verificationsDir, processedSubmissionsDir, submitConfig)
	if err != nil {
		le.Fatalf("Submission failed: %v", err)
	}
}

func processSubmissionDir(submDir, verDir, doneSubmDir string, submitConfig submit.Config) error {
	verFileCount, err := os.ReadDir(verDir)
	if err != nil {
		return fmt.Errorf("Failed to read directory '%s': %w", verDir, err)
	}
	if len(verFileCount) != 0 {
		return fmt.Errorf("Verification directory must be empty")
	}

	doneSubmFileCount, err := os.ReadDir(doneSubmDir)
	if err != nil {
		return fmt.Errorf("Failed to read directory '%s': %w", doneSubmDir, err)
	}
	if len(doneSubmFileCount) != 0 {
		return fmt.Errorf("Processed submission directory must be empty")
	}

	entries, err := os.ReadDir(submDir)
	if err != nil {
		return fmt.Errorf("Failed to read directory '%s': %w", submDir, err)
	}

	for _, entry := range entries {
		var submission submission.Submission
		err := submission.FromFile(path.Join(submDir, entry.Name()))
		if err != nil {
			return fmt.Errorf("Invalid submission file: %w", err)
		}
	}

	for _, entry := range entries {
		err = processSubmissionFile(
			entry.Name(),
			submDir,
			verDir,
			doneSubmDir,
			submitConfig,
		)
		if err != nil {
			return fmt.Errorf("Failed to process submission file: %v", err)
		}
	}

	return nil
}

func processSubmissionFile(fn, submDir, verDir, doneSubmDir string, submitConfig submit.Config) error {
	submissionPath := path.Join(submDir, fn)
	doneSubmissionPath := path.Join(doneSubmDir, fn)
	verificationPath := path.Join(verDir, fn)

	var submission submission.Submission
	err := submission.FromFile(submissionPath)
	if err != nil {
		return fmt.Errorf("Failed to open submission file: %w", err)
	}

	proofText, err := logDevice(submission.Request, submitConfig)
	if err != nil {
		return fmt.Errorf("Failed to log device: %w", err)
	}

	verification := verification.Verification{
		Type:      verification.VerProof,
		Timestamp: submission.Timestamp,
		AppTag:    submission.AppTag,
		AppHash:   submission.AppHash,
		Proof:     proofText,
	}
	err = verification.ToFile(verificationPath)
	if err != nil {
		return fmt.Errorf("Failed to store verification file: %w", err)
	}

	os.Rename(submissionPath, doneSubmissionPath)

	return nil
}

func logDevice(req requests.Leaf, submitConfig submit.Config) (proof.SigsumProof, error) {
	ctx := context.Background()
	reqs := []requests.Leaf{req}

	proofs, err := submit.SubmitLeafRequests(ctx, &submitConfig, reqs)
	if err != nil {
		return proof.SigsumProof{}, fmt.Errorf("Failed to submit sigsum log request: %w", err)
	}
	if len(proofs) != 1 {
		return proof.SigsumProof{}, fmt.Errorf("Expected one proof from log, got %d", len(proofs))
	}

	return proofs[0], nil
}
