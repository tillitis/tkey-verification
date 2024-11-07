# SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
# SPDX-License-Identifier: BSD-2-Clause

source = ["dist/tkey-verification_darwin_all/tkey-verification"]
bundle_id = "com.tillitis.tkey-verification"

apple_id {
  username = "[email protected]"
  password = "@keychain:[email protected]"
  provider = "34722S433A"
}

sign {
  application_identity = "Developer ID Application: Tillitis AB"
}
