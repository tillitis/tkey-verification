# Release notes

## v1.0.0

This version brings a lot of refactoring, aiming at simplifying
building and program structure. Only the major changes
will be mentioned here, see [complete
changelog](https://github.com/tillitis/tkey-verification/compare/v0.0.3...v1.0.0)
for more details.

Changes:
- Refactoring, giving a new way of accessing internal assets, making
  it more idiomatic
- Signer binaries are now checked in to the repo under
  cmd/tkey-verification/bins
- Verisinger-0.0.3 is deprecated, but buildable from older tags
- New singer app included, signer-v1.0.1, built from
  tkey-device-signer without touch
- Support multiple vendor signing keys
- Earlier `show-pubkey` program is now a command in tkey-verification
- Use tkeyclient instead of internal pkg
- Use tkeysign instead of internal pkg
- Refine errors to present more sensible errors to users of the verify
  command
- Pointing to tillitis.se/verify if an error occur when verifying a
  TKey, with explanations to common errors
- Use GoReleaser for release building
- Enable CGO for Darwin, to find the port automatically
- Add `--speed` flag to support multiple baudrates

## v0.0.3

Update to include new TKey product revision from Tillitis which is
based on the FPGA design and bitstream in release:

https://github.com/tillitis/tillitis-key1/releases/tag/TK1-24.03

## v0.0.2

In this second release we ensure that the published executable
binaries can be reproduced, see
[README.md](https://github.com/tillitis/tkey-verification#readme) in
the repository.

Verifying your TKey in a few simple steps:

- download the suitable `tkey-verification` binary for your platform
- rename the file to `tkey-verification` (add `.exe` on Windows, on
  other platforms run: `chmod +x ./tkey-verification`)
- plug in your TKey
- In a terminal on Linux, or in PowerShell on Windows, you can run the
  verification with:

   ```
   ./tkey-verification verify
   ```

- On MacOS, automatic detection of the serial port is currently not
available. You have to first list the serial port devices with:

   ```
   ls -l /dev/cu.*
   ```

   The TKey device name looks like “/dev/cu.usbmodemN” where N is a
   number. Now you can run the verification like:

   ```
   ./tkey-verification verify --port /dev/cu.usbmodemN
   ```

The default operation of `tkey-verification` requires Internet
connectivity to download the verification data on the machine where
you plug in your TKey. But it is also possible to run the verification
on a machine that does not have connectivity, by first downloading the
verification data on a machine which does. See `tkey-verification
verify --help` for more information.

After processing the data and talking to your TKey, expect a final
message saying `TKey is genuine!`.


## v0.0.1

This is the first release of the tool for Tillitis signing and you
verifying that your TKey is genuine.

Verifying your TKey in a few simple steps:
- download the suitable `tkey-verification` binary for your platform
- rename the file to `tkey-verification` (add `.exe` on Windows; do `chmod
  +x ./tkey-verification` on other platforms)
- plug in your TKey
- execute this command in your terminal: `./tkey-verification verify`
(without ./ on Windows)

The default operation of `tkey-verification` requires Internet
connectivity to download the verification data on the machine where
you plug in your TKey. But it is also possible to run the verification
on a machine that does not have connectivity, by first downloading the
verification data on machine which does. See `tkey-verification verify
--help` for more information.

After processing the data and talking to your TKey, expect a final
message saying `TKey is genuine!`.
