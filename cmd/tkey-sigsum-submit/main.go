// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"

	"github.com/spf13/pflag"
	"github.com/tillitis/tkey-verification/internal/sigsum"
	"github.com/tillitis/tkey-verification/internal/submission"
	"github.com/tillitis/tkey-verification/internal/util"
	"github.com/tillitis/tkey-verification/internal/verification"
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

	if verificationsDir == processedSubmissionsDir {
		le.Printf("processed-submissions-dir and verification-dir cannot be the same.\n\n")
		pflag.Usage()
		os.Exit(1)
	}

	var log sigsum.Log
	err := log.FromEmbedded()
	if err != nil {
		le.Fatalf("Sigsum configuration missing")
	}

	submit := SigsumSubmit{
		submDir:     submissionsDir,
		doneSubmDir: processedSubmissionsDir,
		verDir:      verificationsDir,
		log:         log,
	}

	err = submit.processSubmissions()
	if err != nil {
		le.Fatalf("Submission failed: %v", err)
	}
}

type SigsumSubmit struct {
	submDir, verDir, doneSubmDir string
	log                          sigsum.Log

	// HTTPClient specifies the HTTP client to use when making requests to the
	// log.  If nil, a default client is created.
	HTTPClient *http.Client
}

func (s SigsumSubmit) processSubmissions() error {
	verFileCount, err := os.ReadDir(s.verDir)
	if err != nil {
		return fmt.Errorf("failed to read directory '%s': %w", s.verDir, err)
	}
	if len(verFileCount) != 0 {
		return errors.New("verification directory must be empty")
	}

	doneSubmFileCount, err := os.ReadDir(s.doneSubmDir)
	if err != nil {
		return fmt.Errorf("failed to read directory '%s': %w", s.doneSubmDir, err)
	}
	if len(doneSubmFileCount) != 0 {
		return errors.New("processed submission directory must be empty")
	}

	entries, err := os.ReadDir(s.submDir)
	if err != nil {
		return fmt.Errorf("failed to read directory '%s': %w", s.submDir, err)
	}

	for _, entry := range entries {
		var submission submission.Submission
		err = submission.FromFile(path.Join(s.submDir, entry.Name()))
		if err != nil {
			return fmt.Errorf("invalid submission file: %w", err)
		}
	}

	for _, entry := range entries {
		err = s.processSubmissionFile(entry.Name())
		if err != nil {
			return fmt.Errorf("failed to process submission file: %w", err)
		}
	}

	return nil
}

func (s SigsumSubmit) processSubmissionFile(fn string) error {
	submissionPath := path.Join(s.submDir, fn)
	doneSubmissionPath := path.Join(s.doneSubmDir, fn)
	verificationPath := path.Join(s.verDir, fn)

	var submission submission.Submission
	err := submission.FromFile(submissionPath)
	if err != nil {
		return fmt.Errorf("failed to open submission file: %w", err)
	}

	submitConfig := submit.Config{
		Policy:     s.log.Policy,
		HTTPClient: s.HTTPClient,
	}

	proof, err := logDevice(submission.Request, submitConfig)
	if err != nil {
		return fmt.Errorf("failed to log device: %w", err)
	}

	verification := verification.Verification{
		Type:      verification.VerProof,
		Timestamp: submission.Timestamp,
		AppTag:    submission.AppTag,
		AppHash:   submission.AppHash,
		Proof:     proof,
	}

	_, err = verification.VerifyProofDigest(submission.Request.Message, s.log)
	if err != nil {
		return fmt.Errorf("got invalid proof: %w", err)
	}

	err = verification.ToFile(verificationPath)
	if err != nil {
		return fmt.Errorf("failed to store verification file: %w", err)
	}

	err = os.Rename(submissionPath, doneSubmissionPath)
	if err != nil {
		return fmt.Errorf("failed to move verification file: %w", err)
	}

	return nil
}

func logDevice(req requests.Leaf, submitConfig submit.Config) (proof.SigsumProof, error) {
	ctx := context.Background()
	reqs := []requests.Leaf{req}

	proofs, err := submit.SubmitLeafRequests(ctx, &submitConfig, reqs)
	if err != nil {
		return proof.SigsumProof{}, fmt.Errorf("failed to submit sigsum log request: %w", err)
	}
	if len(proofs) != 1 {
		return proof.SigsumProof{}, fmt.Errorf("expected one proof from log, got %d", len(proofs))
	}

	return proofs[0], nil
}
