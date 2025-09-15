// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package sigsum

import (
	"testing"
)

func TestParseEmbedded(t *testing.T) {
	var s Log

	if err := s.FromEmbedded(); err != nil {
		t.Fatal(err)
	}
}

const sigsumConf = `tillitis-sigsum-test
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFDZoSX1HYX/ofsSARva4F054DzaKjXQ2vMHcHLaq7sQ sigsum key
verisigner-v0.0.3
f8ecdcda53a296636a0297c250b27fb649860645626cc8ad935eabb4c43ea3e1841c40300544fade4189aa4143c1ca8fe82361e3d874b42b0e2404793a170142

tillitis-sigsum-test2
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFDZoSX1HYX/ofsSARva4F054DzaKjXQ2vMHcHLaq7sA sigsum key
signer-v1.0.1
cd3c4f433f84648428113bd0a0cc407b2150e925a51b478006321e5a903c1638ce807138d1cc1f8f03cfb6236a87de0febde3ce0ddf177208e5483d1c169bac4
`

// Sigsum policy
const policyStr = `log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye

witness poc.sigsum.org/nisse 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c

group  demo-quorum-rule any poc.sigsum.org/nisse
quorum demo-quorum-rule
`

func TestParse(t *testing.T) {
	var s Log

	if err := s.FromString(sigsumConf, policyStr); err != nil {
		t.Fatal(err)
	}

	if len(s.Keys) != 2 {
		t.Fatal("wrong number of submit keys parsed")
	}
}
