// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package data

//////////////////////////////////////////////////////////////////////
/// Sigsum
//////////////////////////////////////////////////////////////////////

// Public part of the Sigsum Submit key
const SubmitKey = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIONFrsjCVeDB3KwJVsfr/kphaZZZ9Sypuu42ahZBjeya sigsum key`

// Sigsum policy
const PolicyStr = `log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye

witness poc.sigsum.org/nisse 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c

group  demo-quorum-rule any poc.sigsum.org/nisse
quorum demo-quorum-rule
`

//////////////////////////////////////////////////////////////////////
/// Firmwares
//////////////////////////////////////////////////////////////////////
// In this order:
//
// The default/qemu UDI0, with firmware from main at
// TK1-24.03 (1c90b1aa3dbfb4e62039683ee6049ae8af608498)
// UDI 00010203

// Firmware from main at
// c126199a41149f6284aa9533e72395c978733b44
// UDI 01337080

// UDI0 01337081 - first Bellatrix release

// UDI0 01337082 - TK1-24.03 (1c90b1aa3dbfb4e62039683ee6049ae8af608498)

const FirmwaresJSON = `
{
    "fws": [
        {
            "udi0big": "00010203",
            "vendor": 16,
            "product": 8,
            "revision": 3,
            "size": 4160,
            "hash": "06d0aafcc763307420380a8c5a324f3fccfbba6af7ff6fe0facad684ebd69dd43234c8531a096c77c2dc3543f8b8b629c94136ca7e257ca560da882e4dbbb025"
        },

        {
            "udi0big": "01337080",
            "vendor": 4919,
            "product": 2,
            "revision": 0,
            "size": 4192,
            "hash": "3769540390ee3d990ea3f9e4cc9a0d1af5bcaebb82218185a78c39c6bf01d9cdc305ba253a1fb9f3f9fcc63d97c8e5f34bbb1f7bec56a8f246f1d2239867b623"
        },


        {
            "udi0big": "01337081",
            "vendor": 4919,
            "product": 2,
            "revision": 1,
            "size": 4192,
            "hash": "3769540390ee3d990ea3f9e4cc9a0d1af5bcaebb82218185a78c39c6bf01d9cdc305ba253a1fb9f3f9fcc63d97c8e5f34bbb1f7bec56a8f246f1d2239867b623"
        },

        {
            "udi0big": "01337082",
            "vendor": 4919,
            "product": 2,
            "revision": 2,
            "size": 4160,
            "hash": "06d0aafcc763307420380a8c5a324f3fccfbba6af7ff6fe0facad684ebd69dd43234c8531a096c77c2dc3543f8b8b629c94136ca7e257ca560da882e4dbbb025"
        }
    ]
}
`
