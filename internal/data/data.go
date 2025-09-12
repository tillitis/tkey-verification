// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package data

//////////////////////////////////////////////////////////////////////
/// Vendor key
//////////////////////////////////////////////////////////////////////

const VendorPubKeys = `14274d3570097aea209af1c23b64aa439a4d0d32c62735c5f6d6a29600c9a275 verisigner-v0.0.3 f8ecdcda53a296636a0297c250b27fb649860645626cc8ad935eabb4c43ea3e1841c40300544fade4189aa4143c1ca8fe82361e3d874b42b0e2404793a170142`

// Test vendor key.
// const VendorPubKeys = `50d9a125f51d85ffa1fb12011bdae05d39e03cda2a35d0daf3077072daabbb10 verisigner-v0.0.3 f8ecdcda53a296636a0297c250b27fb649860645626cc8ad935eabb4c43ea3e1841c40300544fade4189aa4143c1ca8fe82361e3d874b42b0e2404793a170142`

//////////////////////////////////////////////////////////////////////
/// Sigsum
//////////////////////////////////////////////////////////////////////

// Public part of the Sigsum Submit key
const SubmitKey = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIONFrsjCVeDB3KwJVsfr/kphaZZZ9Sypuu42ahZBjeya sigsum key`

// Test Sigsum submit key corresponding to verisigner-0.3 running on QEMU with test UDS.
// const SubmitKey = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFDZoSX1HYX/ofsSARva4F054DzaKjXQ2vMHcHLaq7sQ sigsum key`

// Sigsum policy
const PolicyStr = `log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye

witness poc.sigsum.org/nisse 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c

group  demo-quorum-rule any poc.sigsum.org/nisse
quorum demo-quorum-rule
`

//////////////////////////////////////////////////////////////////////
/// Firmwares
//////////////////////////////////////////////////////////////////////

const FirmwaresConf = `
# The default/qemu UDI0, with firmware from main at
# TK1-24.03 (1c90b1aa3dbfb4e62039683ee6049ae8af608498)
# UDI 00010203
00010203 0010 8 3 4192 3769540390ee3d990ea3f9e4cc9a0d1af5bcaebb82218185a78c39c6bf01d9cdc305ba253a1fb9f3f9fcc63d97c8e5f34bbb1f7bec56a8f246f1d2239867b623

# Firmware from main at
# c126199a41149f6284aa9533e72395c978733b44
01337080 1337 2 0 4192 3769540390ee3d990ea3f9e4cc9a0d1af5bcaebb82218185a78c39c6bf01d9cdc305ba253a1fb9f3f9fcc63d97c8e5f34bbb1f7bec56a8f246f1d2239867b623

# First Bellatrix release
01337081 1337 2 1 4192 3769540390ee3d990ea3f9e4cc9a0d1af5bcaebb82218185a78c39c6bf01d9cdc305ba253a1fb9f3f9fcc63d97c8e5f34bbb1f7bec56a8f246f1d2239867b623

# TK1-24.03 (1c90b1aa3dbfb4e62039683ee6049ae8af608498)
01337082 1337 2 2 4160 06d0aafcc763307420380a8c5a324f3fccfbba6af7ff6fe0facad684ebd69dd43234c8531a096c77c2dc3543f8b8b629c94136ca7e257ca560da882e4dbbb025
`
