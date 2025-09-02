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

// Submission file built from two TKeys with default UDS. One used as device to
// submit to the log, and the other used as vendor signing key.
//
// Tkey-verification was run like so:
// - go run ./cmd/tkey-verification remote-sign --port /dev/tty-tkey-b-test-device --config tkey-verification.yaml.example-remote-sign
// - go run ./cmd/tkey-verification/ serve-signer --port /dev/tty-tkey-b-test-vendor-key --config tkey-verification.yaml.example-serve-signer
var submFileContent = []byte(`{"timestamp":"2025-09-02T10:56:48Z","apptag":"signer-v1.0.1","apphash":"cd3c4f433f84648428113bd0a0cc407b2150e925a51b478006321e5a903c1638ce807138d1cc1f8f03cfb6236a87de0febde3ce0ddf177208e5483d1c169bac4","request":"message=f23e454ee9c9627dd1a80f6ab2e1565fa0cda3a7c91f853eb8099ff645674719\nsignature=b4f9eabdcb6b05d259e964ba6fa427c178b5586d30e6b4026287656c8a7ee2674af33d2c05701ea8f98458fe7c54b787c7a73c0fda6f09046bcf7604cea86c00\npublic_key=50d9a125f51d85ffa1fb12011bdae05d39e03cda2a35d0daf3077072daabbb10\n"}`)

const polText = `log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 http://sigsumlog.test

	witness testwitness 5c35281928e9da396beede5f22a2251a589e6ac6de52a4de85de8634ffccaf6d

	group  demo-quorum-rule all testwitness

	quorum demo-quorum-rule
	`

var wantVerFileContent = []byte(`{"timestamp":"2025-09-02T10:56:48Z","apptag":"signer-v1.0.1","apphash":"cd3c4f433f84648428113bd0a0cc407b2150e925a51b478006321e5a903c1638ce807138d1cc1f8f03cfb6236a87de0febde3ce0ddf177208e5483d1c169bac4","proof":"version=2\nlog=4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d\nleaf=e7f5de9e44de09b425853f0b267a06fe3eca528c96c8fabd521e5cbfaec83806 b4f9eabdcb6b05d259e964ba6fa427c178b5586d30e6b4026287656c8a7ee2674af33d2c05701ea8f98458fe7c54b787c7a73c0fda6f09046bcf7604cea86c00\n\nsize=4684\nroot_hash=07e183bd7b31636eee13edba7ee64cc586363aea9e7cdd1579c047e2643a87b7\nsignature=9af6929d26d4dfb94802cba6f1cd988ac7165b73bfb1bbd1922175a771b5408056e2605e386a231b13ce7dda089db07beb35e2b387e88fa69e322f8839b01804\ncosignature=0d4f46a219ab309cea48cde9712e7d8486fc99802f873175eeab70fb84b4f5a4 1756811283 8aff7c90eeeb74080bd81948afeb83ba5f25868ed06bb6103da45ecbc70c0dd8a195f6ab792bfa70a0f1af7d7dbd1c5beb480fc13d18f695a6fff9a8bbbb4709\n\nleaf_index=4683\nnode_hash=deed2b128c089094c865ce893aa9898f131460ea539f5ed38dd5a8054e087fd8\nnode_hash=ab8d1b7eb823ad50ffe619017aa14f66cde57a47a6d1739aa06bd64cbbffc91f\nnode_hash=1e2ef1212c516b59b7d3948958be90d8ef58acc427d3b4a558757041c6507db0\nnode_hash=72347e82644eea74e0e3806c16a40b396353c934850b98d9013658f13b99ecb9\nnode_hash=9103c094b7a2cbf2da7c1e1d492906ac0b9062cb0dee3a8e20f5fbff5b219c79\nnode_hash=9ca6b461d616cf790a32a967574087298abb4cd0c3da938b7fed143b7d92b5ec\n"}
`)

func Test_processSubmissionFileShouldGenerateVerificationFileFromSubmissionFile(t *testing.T) {
	submDir := t.TempDir()
	verDir := t.TempDir()
	fn := "0001020304050607"

	err := os.WriteFile(path.Join(submDir, fn), []byte(submFileContent), 0644)
	if err != nil {
		t.Fatalf("Failed setting up input file: %v", err)
	}

	pol, err := policy.ParseConfig(bytes.NewBufferString(polText))
	if err != nil {
		le.Fatalf("Failed to read sigsum policy: %v", err)
	}

	fakeClient := http.Client{Transport: ts.NewFakeTransport()}
	submitConfig := submit.Config{
		HTTPClient: &fakeClient,
		Policy:     pol,
	}

	err = processSubmissionFile(fn, submDir, verDir, submitConfig)
	if err != nil {
		t.Fatalf("Got error when running processSubmissionFile: %v", err)
	}

	verFileContent, err := os.ReadFile(path.Join(verDir, fn))
	if err != nil {
		t.Fatalf("Could not read verification file: %v", err)
	}

	if !bytes.Equal(verFileContent, wantVerFileContent) {
		t.Fatalf("Unexpected verification file content.\nGot:      %q\nExpected: %q",
			verFileContent,
			wantVerFileContent,
		)
	}
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
