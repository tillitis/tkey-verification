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

	"github.com/tillitis/tkey-verification/internal/sigsum"
)

// Test Sigsum submit key corresponding to verisigner-0.3 running on QEMU with test UDS.
const TestSigsumConf = `
tillitis-sigsum-test
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFDZoSX1HYX/ofsSARva4F054DzaKjXQ2vMHcHLaq7sQ sigsum key
verisigner-v0.0.3
f8ecdcda53a296636a0297c250b27fb649860645626cc8ad935eabb4c43ea3e1841c40300544fade4189aa4143c1ca8fe82361e3d874b42b0e2404793a170142
2024-09-16T08:10:33+02:00
2125-09-16T08:11:33+02:00
`

func Test_processSubmissionFileShouldGenerateVerificationFileFromSubmissionFile(t *testing.T) {
	submit := SigsumSubmit{
		submDir:     t.TempDir(),
		doneSubmDir: t.TempDir(),
		verDir:      t.TempDir(),
		HTTPClient:  &http.Client{Transport: ts.NewFakeTransport()},
	}

	policyStr, err := os.ReadFile("testdata/policy")
	if err != nil {
		t.Fatal(err)
	}

	var log sigsum.Log

	if err = log.FromString(TestSigsumConf, string(policyStr)); err != nil {
		t.Fatal(err)
	}

	submit.log = log

	fn := "0001020304050607"
	submFile := path.Join(submit.submDir, fn)
	verFile := path.Join(submit.verDir, fn)

	copyFile(submFile, "testdata/0001020304050607-subm-valid")

	err = submit.processSubmissionFile(fn)
	if err != nil {
		t.Fatalf("Got error when running processSubmissionFile: %v", err)
	}

	assertFileContentsEqual(t, verFile, "testdata/0001020304050607-ver-valid")
}

func Test_processSubmissionDir(t *testing.T) {

	type Params []struct {
		name              string
		preSubmFiles      map[string]string // Sample files to copy from testdata to submissions dir before running. Maps source->destination filename
		preDoneSubmFiles  map[string]string // Sample files to copy from testdata to processed-submissions dir before running. Maps source->destination filename
		preVerFiles       map[string]string // Sample files to copy from testdata to verification dir before running. Maps source->destination filename
		postSubmFiles     map[string]string // Sample files to look for in submissions dir after running. Maps source->destination filename
		postDoneSubmFiles map[string]string // Sample files to look for in processed submissions dir after running. Maps source->destination filename
		postVerFiles      map[string]string // Sample files to look for in verifications dir after running. Maps source->destination filename
		errString         string            // Expected error string. Use empty string if error is expected to be nil.
	}

	tests := Params{
		{
			name:              "One valid submission file generates one verification file",
			preSubmFiles:      map[string]string{"0001020304050607-subm-valid": "0001020304050607"},
			preDoneSubmFiles:  map[string]string{},
			preVerFiles:       map[string]string{},
			postSubmFiles:     map[string]string{},
			postDoneSubmFiles: map[string]string{"0001020304050607-subm-valid": "0001020304050607"},
			postVerFiles:      map[string]string{"0001020304050607-ver-valid": "0001020304050607"},
			errString:         "",
		},
		{
			name:              "Should abort if verification directory is not empty on start",
			preSubmFiles:      map[string]string{"0001020304050607-subm-valid": "0001020304050607"},
			preDoneSubmFiles:  map[string]string{},
			preVerFiles:       map[string]string{"0001020304050607-ver-valid": "0001020304050607"},
			postSubmFiles:     map[string]string{"0001020304050607-subm-valid": "0001020304050607"},
			postDoneSubmFiles: map[string]string{},
			postVerFiles:      map[string]string{"0001020304050607-ver-valid": "0001020304050607"},
			errString:         "verification directory must be empty",
		},
		{
			name:              "Should abort if processed submissions directory is not empty on start",
			preSubmFiles:      map[string]string{"0001020304050607-subm-valid": "0001020304050607"},
			preDoneSubmFiles:  map[string]string{"0001020304050607-subm-valid": "0001020304050607"},
			preVerFiles:       map[string]string{},
			postSubmFiles:     map[string]string{"0001020304050607-subm-valid": "0001020304050607"},
			postDoneSubmFiles: map[string]string{"0001020304050607-subm-valid": "0001020304050607"},
			postVerFiles:      map[string]string{},
			errString:         "processed submission directory must be empty",
		},
		{
			name: "Should abort if any submission file is invalid",
			preSubmFiles: map[string]string{
				"0001020304050607-subm-valid":       "0001020304050607",
				"000102030400DEAD-subm-invalid-sig": "000102030400DEAD",
			},
			preDoneSubmFiles: map[string]string{},
			preVerFiles:      map[string]string{},
			postSubmFiles: map[string]string{
				"0001020304050607-subm-valid":       "0001020304050607",
				"000102030400DEAD-subm-invalid-sig": "000102030400DEAD",
			},
			postDoneSubmFiles: map[string]string{},
			postVerFiles:      map[string]string{},
			errString:         "invalid submission file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()

			submit := SigsumSubmit{
				submDir:     path.Join(tempDir, "submissions"),
				doneSubmDir: path.Join(tempDir, "processed"),
				verDir:      path.Join(tempDir, "verifications"),
				HTTPClient:  &http.Client{Transport: ts.NewFakeTransport()},
			}

			copySamplesToDir(submit.submDir, tt.preSubmFiles)
			copySamplesToDir(submit.verDir, tt.preVerFiles)
			copySamplesToDir(submit.doneSubmDir, tt.preDoneSubmFiles)

			policyStr, err := os.ReadFile("testdata/policy")
			if err != nil {
				t.Fatal(err)
			}

			var log sigsum.Log

			if err = log.FromString(TestSigsumConf, string(policyStr)); err != nil {
				t.Fatal(err)
			}

			submit.log = log

			err = submit.processSubmissions()

			assertErrorMsgStartsWith(t, err, tt.errString)
			assertDirContainsOnly(t, submit.submDir, tt.postSubmFiles)
			assertDirContainsOnly(t, submit.doneSubmDir, tt.postDoneSubmFiles)
			assertDirContainsOnly(t, submit.verDir, tt.postVerFiles)
		})
	}
}

func assertErrorMsgStartsWith(t *testing.T, err error, errString string) {
	t.Helper()

	if errString == "" {
		// Expecting nil
		if err != nil {
			t.Logf("Unexpected error %v", err)
			t.Fail()
		}
	} else {
		// Expecting error
		if err == nil || !strings.HasPrefix(err.Error(), errString) {
			t.Logf("Unexpected error '%v', should start with '%v'", err, errString)
			t.Fail()
		}
	}
}

// Assert that directory dir only contains the files in specified in samples.
// The contents of each file is checked for equality with the contents of its
// corresponding sample file located in the testdata directory.
func assertDirContainsOnly(t *testing.T, dir string, samples map[string]string) {
	t.Helper()

	assertFileCount(t, dir, len(samples))
	for sampleFn, createdFn := range samples {
		createdFile := path.Join(dir, createdFn)
		samplePath := path.Join("testdata", sampleFn)
		assertFileContentsEqual(t, createdFile, samplePath)
	}
}

// Copy files from directory testdata to dstDir. `samples` maps source filename
// to destination filename.
func copySamplesToDir(dstDir string, samples map[string]string) {
	mustCreateDir(dstDir)
	for srcFn, dstFn := range samples {
		dstPath := path.Join(dstDir, dstFn)
		srcPath := path.Join("testdata", srcFn)
		copyFile(dstPath, srcPath)
	}
}

func copyFile(dstPath string, srcPath string) {
	srcData, err := os.ReadFile(srcPath)
	if err != nil {
		msg := fmt.Sprintf("Could not copy file: %v", err)
		panic(msg)
	}

	err = os.WriteFile(dstPath, srcData, 0600)
	if err != nil {
		msg := fmt.Sprintf("Could not copy to file: %v", err)
		panic(msg)
	}
}

func assertFileCount(t *testing.T, dir string, wantCount int) {
	t.Helper()

	count := len(mustListFiles(dir))
	if count != wantCount {
		t.Logf("Folder '%s' contains %d files, wanted %d.", dir, count, wantCount)
		t.Fail()
	}
}

func mustListFiles(dir string) []os.DirEntry {
	entries, err := os.ReadDir(dir)
	if err != nil {
		msg := fmt.Sprintf("Failed to read directory '%s': %v", dir, err)
		panic(msg)
	}

	return entries
}

func mustCreateDir(path string) {
	err := os.Mkdir(path, 0700)
	if err != nil {
		msg := fmt.Sprintf("Failed to create directory '%s': %v", path, err)
		panic(msg)
	}
}

func assertFileContentsEqual(t *testing.T, aPath string, bPath string) {
	t.Helper()

	aData, err := os.ReadFile(aPath)
	if err != nil {
		t.Fatalf("Could not read file: %v", err)
	}

	bData, err := os.ReadFile(bPath)
	if err != nil {
		t.Fatalf("Could not read file: %v", err)
	}

	if !bytes.Equal(aData, bData) {
		t.Logf("Contents of '%s' and '%s' are not equal", aPath, bPath)
		t.Fail()
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
		}
		ts.setLeafWasCalled(ft)

		return &http.Response{StatusCode: http.StatusAccepted}, nil
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

	errStr := "Fake server got unexpected URL: %s" + req.URL.String()
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
