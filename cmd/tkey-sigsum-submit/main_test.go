// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"os"
	"path"
	"testing"

	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/submit"
)

func Test_processSubmissionFileShouldGenerateVerificationFileFromSubmissionFile(t *testing.T) {
	submDir := t.TempDir()
	verDir := t.TempDir()
	fn := "0001020304050607"
	submFile := path.Join(submDir, fn)
	verFile := path.Join(verDir, fn)

	copyFile(submFile, "testdata/submissions/0001020304050607")
	pol := mustReadPolicyFile("testdata/policy")
	fakeClient := http.Client{Transport: ts.NewFakeTransport()}
	submitConfig := submit.Config{
		HTTPClient: &fakeClient,
		Policy:     pol,
	}

	err := processSubmissionFile(fn, submDir, verDir, submitConfig)
	if err != nil {
		t.Fatalf("Got error when running processSubmissionFile: %v", err)
	}

	requireFileContentEqual(t, verFile, "testdata/verifications/0001020304050607")
}

func copyFile(dstPath string, srcPath string) {
	srcData, err := os.ReadFile(srcPath)
	if err != nil {
		msg := fmt.Sprintf("Could not copy file: %v", err)
		panic(msg)
	}

	err = os.WriteFile(dstPath, srcData, 0644)
	if err != nil {
		msg := fmt.Sprintf("Could not copy to file: %v", err)
		panic(msg)
	}
}

func requireFileContentEqual(t *testing.T, aPath string, bPath string) {
	aData, err := os.ReadFile(aPath)
	if err != nil {
		t.Fatalf("Could not read file: %v", err)
	}

	bData, err := os.ReadFile(bPath)
	if err != nil {
		t.Fatalf("Could not read file: %v", err)
	}

	if !bytes.Equal(aData, bData) {
		t.Fatalf("Contents of '%s' and '%s' are not equal", aPath, bPath)
	}
}

func mustReadPolicyFile(path string) *policy.Policy {
	pol, err := policy.ReadPolicyFile(path)
	if err != nil {
		msg := fmt.Sprintf("Failed to read sigsum policy: %v", err)
		panic(msg)
	}

	return pol
}

// fakeTransport is an HTTP Transport faking a Sigsum Log. Just enough behavior
// is faked to make it possible for a client to add a predetermined leaf and
// generate a predetermined proof.
//
// Will panic if the 'add-leaf' request body has unexpected content.
// Will panic when accessing an unexpected URL.
// Will panic on run time errors.
type fakeTransport struct {
	cacheIndex int
}

func (ft fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	const addLeafURL = "http://sigsumlog.test/add-leaf"
	const expectedAddLeafRequestBody = `message=f23e454ee9c9627dd1a80f6ab2e1565fa0cda3a7c91f853eb8099ff645674719
signature=b4f9eabdcb6b05d259e964ba6fa427c178b5586d30e6b4026287656c8a7ee2674af33d2c05701ea8f98458fe7c54b787c7a73c0fda6f09046bcf7604cea86c00
public_key=50d9a125f51d85ffa1fb12011bdae05d39e03cda2a35d0daf3077072daabbb10
`
	const getTreeHeadURL = "http://sigsumlog.test/get-tree-head"
	const getTreeHeadResponseBody = `size=4684
root_hash=07e183bd7b31636eee13edba7ee64cc586363aea9e7cdd1579c047e2643a87b7
signature=9af6929d26d4dfb94802cba6f1cd988ac7165b73bfb1bbd1922175a771b5408056e2605e386a231b13ce7dda089db07beb35e2b387e88fa69e322f8839b01804
cosignature=0d4f46a219ab309cea48cde9712e7d8486fc99802f873175eeab70fb84b4f5a4 1756811283 8aff7c90eeeb74080bd81948afeb83ba5f25868ed06bb6103da45ecbc70c0dd8a195f6ab792bfa70a0f1af7d7dbd1c5beb480fc13d18f695a6fff9a8bbbb4709
`
	const getInclusionProofURL = "http://sigsumlog.test/get-inclusion-proof/4684/eca101878ff4cad7aac85f70ed41e5d9e04544b84be6b3ab2834df49496680e6"
	const getInclusionProofResponseBody = `leaf_index=4683
node_hash=deed2b128c089094c865ce893aa9898f131460ea539f5ed38dd5a8054e087fd8
node_hash=ab8d1b7eb823ad50ffe619017aa14f66cde57a47a6d1739aa06bd64cbbffc91f
node_hash=1e2ef1212c516b59b7d3948958be90d8ef58acc427d3b4a558757041c6507db0
node_hash=72347e82644eea74e0e3806c16a40b396353c934850b98d9013658f13b99ecb9
node_hash=9103c094b7a2cbf2da7c1e1d492906ac0b9062cb0dee3a8e20f5fbff5b219c79
node_hash=9ca6b461d616cf790a32a967574087298abb4cd0c3da938b7fed143b7d92b5ec
`

	switch req.URL.String() {
	case addLeafURL:
		body, err := io.ReadAll(req.Body)
		if err != nil {
			panic("Fake server could not read 'add-leaf' body")
		}

		if string(body) != expectedAddLeafRequestBody {
			panic("Fake server got unexpected 'add-leaf' body")
		}

		if ts.getLeafWasCalled(ft) {
			return &http.Response{StatusCode: http.StatusOK}, nil
		} else {
			ts.setLeafWasCalled(ft)
			return &http.Response{StatusCode: http.StatusAccepted}, nil
		}
	case getTreeHeadURL:
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(getTreeHeadResponseBody)),
		}, nil
	case getInclusionProofURL:
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(getInclusionProofResponseBody)),
		}, nil
	}

	errStr := fmt.Sprintf("Fake server got unexpected URL: %s", req.URL.String())
	panic(errStr)
}

// transportStates is a thread safe storage used by fakeTransport to store
// state between requests
type transportStates struct {
	addLeafWasCalled []bool
	lock             sync.Mutex
}

func (ts *transportStates) NewFakeTransport() fakeTransport {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	i := len(ts.addLeafWasCalled)
	ts.addLeafWasCalled = append(ts.addLeafWasCalled, false)
	return fakeTransport{cacheIndex: i}
}

func (ts *transportStates) setLeafWasCalled(ft fakeTransport) {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	ts.addLeafWasCalled[ft.cacheIndex] = true
}

func (ts *transportStates) getLeafWasCalled(ft fakeTransport) bool {
	ts.lock.Lock()
	defer ts.lock.Unlock()

	return ts.addLeafWasCalled[ft.cacheIndex]
}

var ts = transportStates{}
