// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package data

// Public part of the Sigsum Submit key
const SubmitKey = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIONFrsjCVeDB3KwJVsfr/kphaZZZ9Sypuu42ahZBjeya sigsum key`

// Sigsum policy
const PolicyStr = `log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye

witness poc.sigsum.org/nisse 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c

group  demo-quorum-rule any poc.sigsum.org/nisse
quorum demo-quorum-rule
`
