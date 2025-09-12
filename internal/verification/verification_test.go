// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package verification

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/tillitis/tkey-verification/internal/sigsum"
	"github.com/tillitis/tkey-verification/internal/util"
	"github.com/tillitis/tkey-verification/internal/vendorkey"
	sumcrypto "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
)

const submitKey = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIONFrsjCVeDB3KwJVsfr/kphaZZZ9Sypuu42ahZBjeya sigsum key`

const policyStr = `log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye

witness poc.sigsum.org/nisse 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c

group  demo-quorum-rule any poc.sigsum.org/nisse
quorum demo-quorum-rule
`

const verificationSigJSON = `
{
  "timestamp": "2023-03-03T09:31:51Z",
  "apptag":"verisigner-v0.0.3",
  "apphash":"f8ecdcda53a296636a0297c250b27fb649860645626cc8ad935eabb4c43ea3e1841c40300544fade4189aa4143c1ca8fe82361e3d874b42b0e2404793a170142",
  "signature":"e30f47287220a6aa0553cb93ca38f60eb0601fa5f802dc15d7be13447ea4f57308a94137543c5492606cb4b69eaa6f9618e7806d588c391fdd83cd920dcf230c"
}
`

const verificationProofJSON = `
{
  "timestamp": "2023-03-03T09:31:51Z",
  "apptag":"verisigner-v0.0.3",
  "apphash":"f8ecdcda53a296636a0297c250b27fb649860645626cc8ad935eabb4c43ea3e1841c40300544fade4189aa4143c1ca8fe82361e3d874b42b0e2404793a170142",
  "proof": "version=1\nlog=4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d\nleaf=ca78 f3744a4d05231ceed5d704e7fcdd8ee436f2253d980cf5716ae34cc16c06f439 acd7edc4e9483b4bc3aee2ada2c7b08ac5868e762a024420e94e82ef0ab0dc3f480bf89bde6a88906bacd183b79a8803e72ab507fd3c40d60a2200ca912a1208\n\nsize=4473\nroot_hash=b09a7824a111f11e1ea00b1e76735eba200284830e3fa6fee84d8d556bacb1b8\nsignature=6414fa4fb92d42c067675299c7a3fb2ad4e926e0960f29dd7efca63df2602975b580873f49baa6fb5477f8ec0db26a2b8eac9787d18c025643ea45b89060ac02\ncosignature=70b861a010f25030de6ff6a5267e0b951e70c04b20ba4a3ce41e7fba7b9b7dfc 1756222257 08a623f83c5dfc33cac5c76370f8436920dd9a9428c52c9958075fc6ec54c11295acbc648c580a88d9a9c8cbc10f9075f055ba39848e75734a04429e80ccdf09\ncosignature=b95ef35a9ffb3cf516f423a04128d37d3bffc74d4096bd5e967990c53d09678a 1756222257 7f6ca5349f054d7a375054c5718dcfa864f245d45d273085ff939aeaed2391ed072fae13d92f8374afb0ae48b6f3b2d787a928518330fee71de0450e7ad39906\ncosignature=0d4f46a219ab309cea48cde9712e7d8486fc99802f873175eeab70fb84b4f5a4 1756222257 5685321ea3776687d12efeb398d09723f00092ed007a482f2a13a66270442b2e639a6b9faa2d7a6481be5dc6927447244fd04b959cc468cb4c774b8022e74604\ncosignature=49c4cd6124b7c572f3354d854d50b2a4b057a750f786cf03103c09de339c4ea3 1756222257 03bc716a896f16a97f3328e2efb340eaf13d224c42d51825c0acffda9080cd388e0b304d55f55205d01ebfb3f334ae2bf11494c83aff481a4519e7790c7b150a\ncosignature=1c997261f16e6e81d13f420900a2542a4b6a049c2d996324ee5d82a90ca3360c 1756222257 83d5f8bcdb33e82082c7f8969f7a798687838074ac086fd99bdb677df0275363fc957d6cd63d3462ac88392b3a5d03e0d7eead34ba28d64bf030ac9354b53a0c\ncosignature=42351ad474b29c04187fd0c8c7670656386f323f02e9a4ef0a0055ec061ecac8 1756222257 25791a84085b014e0357acaf68425abf8a8c0f33f754d521b935972ae2a7fdbe8f939e9ce173145aefc3b8d814162dbd627f0a72edb4655b13ac9864879c6808\n\nleaf_index=4472\nnode_hash=c52527e8f58d5e11428c85c8308892cb22383437d2a8428a37335c4b461b640e\nnode_hash=730ccb8fa755d9bbcb3282b9dc8f7e0900c21d0110287efcc0580f5b6cd298ec\nnode_hash=454c7b728002a36a48db60d03a2e3c0eccf043b8e3179ef1aebcc97baf8bde62\nnode_hash=0103bb70827f682b599c65fb22ef2b53ab26ec590c6b2aae920ded4065514f89\nnode_hash=aa56901f083cdabbaaa1ac1066b2b7d2910b9cff7803991a6a18e080e3c71f7a\nnode_hash=9ca6b461d616cf790a32a967574087298abb4cd0c3da938b7fed143b7d92b5ec\n"
}
`

func TestParseVerification(t *testing.T) {
	var v Verification

	if err := v.FromJSON([]byte(verificationProofJSON)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifySignature(t *testing.T) {
	var v Verification

	udi := []byte{0, 1, 2, 3, 4, 5, 6, 7}

	// Create test vendor keys
	var vendorKeys vendorkey.VendorKeys

	seed := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	privKey := ed25519.NewKeyFromSeed(seed)

	var pubKey vendorkey.PubKey
	copy(pubKey.PubKey[:], privKey[32:])

	vendorKeys.Keys = map[string]vendorkey.PubKey{
		"key": pubKey,
	}

	fwDigest, err := hex.DecodeString("3769540390ee3d990ea3f9e4cc9a0d1af5bcaebb82218185a78c39c6bf01d9cdc305ba253a1fb9f3f9fcc63d97c8e5f34bbb1f7bec56a8f246f1d2239867b623")
	if err != nil {
		t.Fatal(err)
	}

	// Build a message.
	// Let's just reuse the test vendor pubkey as the signer's pubkey
	msg, err := util.BuildMessage(udi, fwDigest, pubKey.PubKey[:])
	if err != nil {
		t.Fatal(err)
	}

	// Keep to create test data. Sign and output both key pair and signature:
	// sig := ed25519.Sign(privKey, msg)
	// fmt.Printf("privkey: %x\npubkey: %x\nsig: %x\ndigest: %x\n", privKey, pubKey.PubKey, sig, sha256.Sum256(msg))

	if err := v.FromJSON([]byte(verificationSigJSON)); err != nil {
		t.Fatal(err)
	}

	_, err = v.VerifySig(msg, vendorKeys)
	if err != nil {
		t.Fatal("vendor signature verification failed")
	}
}

func TestVerifyProofRawHash(t *testing.T) {
	var v Verification
	var log sigsum.SigsumLog

	if err := log.FromString(submitKey, policyStr); err != nil {
		t.Fatal(err)
	}

	digest, err := sumcrypto.HashFromHex("2291327fbadd2b3b8f8c0c005426700ad9139425a52a9140679e89b3b65c359b")
	if err != nil {
		t.Fatal(err)
	}

	if err := v.FromJSON([]byte(verificationProofJSON)); err != nil {
		t.Fatal(err)
	}

	if err := v.VerifyProofDigest(digest, *log.Policy, log.SubmitKeys); err != nil {
		t.Fatal("vendor signature not verified")
	}
}

func TestVerifyProof(t *testing.T) {
	var v Verification
	var log sigsum.SigsumLog

	if err := log.FromString(submitKey, policyStr); err != nil {
		t.Fatal(err)
	}

	if err := v.FromJSON([]byte(verificationProofJSON)); err != nil {
		t.Fatal(err)
	}

	// Build a message

	udi := []byte{0, 1, 2, 3, 4, 5, 6, 7}

	fwDigest, err := hex.DecodeString("3769540390ee3d990ea3f9e4cc9a0d1af5bcaebb82218185a78c39c6bf01d9cdc305ba253a1fb9f3f9fcc63d97c8e5f34bbb1f7bec56a8f246f1d2239867b623")
	if err != nil {
		t.Fatal(err)
	}

	signerPubKey, err := hex.DecodeString("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")
	if err != nil {
		t.Fatal(err)
	}

	msg, err := util.BuildMessage(udi, fwDigest, signerPubKey)
	if err != nil {
		t.Fatal(err)
	}

	if err := v.VerifyProof(msg, *log.Policy, log.SubmitKeys); err != nil {
		t.Fatal("vendor signature not verified")
	}
}

func mustParsePublicKey(ascii string) sumcrypto.PublicKey {
	key, err := key.ParsePublicKey(ascii)
	if err != nil {
		panic(err)
	}
	return key
}
