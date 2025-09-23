# Tillitis TKey Verification

`tkey-verification` and its associated programs are tools used for
signing a TKey identity and verifying that the same TKey still has the
same identity later. See [Design of the TKey verification
process](doc/design.md) for all the details.

The verification of this identity does not prove that the TKey hasn't
been tampered with, only that the identity of an app running on it is
the same and, to a lesser degree, that it still runs the same
firmware.

*Note well*: If your TKey wasn't provisioned by Tillitis, and instead
by another "vendor" like your IT department, you will need to run
their version of the `tkey-verification` program instead of this one.

## Installation

[Official
instructions](https://www.tillitis.se/applications/tkey-device-verification/)
on Tillitis' web.

There are three programs:

- tkey-verification: Used for provisioning by the vendor.
- tkey-sigsum-submit: Used for submitting signed requests to a Sigsum
  log by the vendor.
- tkey-verify: Used to verify a Tillitis TKey.

You can download releases of the tools at:

https://github.com/tillitis/tkey-verification/releases

Or use `go install`. If you're and end user you probably only want
`tkey-verify`, like this:

```
$ go install github.com/tillitis/tkey-verification/cmd/tkey-verify@latest
```

If you want to build static binaries from source running `make` or
`make podman` using our tkey-builder OCI image should suffice, but
note [Releases of tkey-verification and reproducible
builds](releases-of-tkey-verification-and-reproducible builds) below.

## Usage by end user

For the typical end user with network access, insert the TKey and run:

```
$ tkey-verify
```

For more advanced use, see the man page in `doc/tkey-verify.1`.

## Usage by vendor

For use during provisioning, use the `tkey-verification` and
`tkey-sigsum-submit` programs. See the man pages in
`doc/tkey-verification.1` and `doc/tkey-sigsum-submit.1` for details.

Basically, `tkey-verification` has two sub-commands, *serve-signer*
for use as a server on a HSM-like machine with a vendor TKey, and
*remote-sign* for the provisioning station.

The server produces submission files with a signed request to log to a
Sigsum transparency log.

Use `tkey-sigsum-request` to submit the submission files to the log,
collect Sigsum proofs, and to produce verification files.

Finally, publish the verification files in the URL `tkey-verify` uses.
For Tillitis, this is:

https://tkey.tillitis.se/verify/UDI-in-hex

like this:

https://tkey.tillitis.se/verify/0133708100000002

This diagram contains an overview of how data flows during
provisioning at Tillitis:

![Data flow during provisioning](signing-procedure.svg)

## Test setup

You need two TKeys. It might be easier to use one physical TKey and
one emulated (see [QEMU chapter in Tillitis Developer
Handbook](https://dev.tillitis.se/tools/#qemu-emulator). One is used
for the vendor's signing TKey. The other is a TKey that you want to
sign and then verify as genuine. You need to know the serial port
device paths for both of them.

Here we are using `run-tkey-qemu` from
[tkey-devtools](https://github.com/tillitis/tkey-devtools) as the
vendor TKey:

```
$ run-tkey-qemu
$ ./tkey-verification serve-signer --config tkey-verification.yaml.example-serve-signer --port ./tkey-qemu-pty
```

Insert the device under verification, the TKey to be signed by the
vendor, then:

```
$ ./tkey-verification remote-sign --config tkey-verification.yaml.example-remote-sign
Auto-detected serial port /dev/ttyACM0
Connecting to device on serial port /dev/ttyACM0 ...
Firmware name0:'tk1 ' name1:'mkdf' version:4
Loading verisigner-app built from tag:verisigner-v0.0.1 hash:9598910ec9ebe2504a5f894de6f8e067… ...
App loaded.
App name0:'veri' name1:'sign' version:1
TKey UDI: 0x0001020304050607(BE) VendorID: 0x0010 ProductID: 8 ProductRev: 3
TKey firmware with size:3204 and verified hash:31accb1c40febc2bf02f48656a943336…
Remote Sign was successful
```

The signing server should now have signed and saved a submit request
file under `signatures` with a filename generated from the Unique
Device Identifier, typically something like `0133704100000015` if from
Tillitis, but `0001020304050607` if the bitstream has been built
directly from
[tillitis-key1](https://github.com/tillitis/tillitis-key1).

To submit the TKey Identity using the submit request file, first
create two empty directories to hold the processed submit request file
and the generated verification file. Then run `tkey-sigsum-submit`:

```
$ mkdir processed-submissions
$ mkdir verifications
$ ./tkey-sigsum-submit -m signatures -n processed-submissions -d verifications
2025/05/04 12:04:34 [INFO] Attempting to submit checksum#1 to log: https://test.sigsum.org/barreleye
2025/05/04 12:04:35 [INFO] Attempting to retrieve proof for checksum#1
```

There should now be a verification file in the `verifications` directory.

Before trying to verify you need to remove and re-insert the device
under verification to get it back to firmware mode. Then run
`tkey-verify -d verifications` to point to local verification files in
a directory rather than requesting them over the Internet:

```
$ ./tkey-verify -d verifications
TKey UDI: 0x0001020304050607(BE) VendorID: 0x0010 ProductID: 8 ProductRev: 3
Verified Sigsum proof. Submit key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFDZoSX1HYX/ofsSARva4F054DzaKjXQ2vMHcHLaq7sQ sigsum key

TKey is genuine!
```

For the complete set of commands, see the manual pages
[tkey-verify(1)](doc/tkey-verify.1) and
[tkey-verification(1)](doc/tkey-verification.1)

## Certificates

For your testing convenience we include a test CA and some test
certificates in `certs`. They expire 10 years after being generated.

If you need to rebuild CA, server, and client certs you can use any
ordinary X.509 certificate tools like GnuTLS's certtool or OpenSSL to
generate your certificates.

You can also install the small [certstrap
tool](https://github.com/square/certstrap) and run:

```
$ make certs
```

## Maintenance

There are some compiled-in assets. Most of these are in
[internal/data/data.go](internal/data/data.go).

- Application binaries: The device apps used for both vendor signing
  and device authentication. See below how to maintain.

- Vendor public keys: The public key from a vendor TKey used for
  verification. Might be several, including historical keys. *No
  longer* used for signing, but still used for verification. See the
  constant `VendorPubKeys`.

- Sigsum configuration including the Sigsum submit keys which replaces
  the old vendor public keys, see the `SigsumConf` and `PolicyStr`
  constants.

- Known firmwares: Expected firmwares for all known TKey models from
  the vendor (first half of the Unique Device Identifier). See the
  `FirmwaresConf` constant.

Commands are responsible for initializing their own assets. For
instance, `tkey-verify` needs all of the above, `remote-sign` needs
the application binaries and the firmwares, `serve-signer` needs
application binaries and the Sigsum configuration.

## Included device app binaries

The device apps used for signing is included in binary form under
`internal/appbins/bins`. They are stored like this:

- `name-tag`, like `signer-v1.0.1.bin`: the actual device app binary.
- `name-tag.sha512`, like `signer-v1.0.1.bin.sha512`: the SHA-512
  digest of the above file to help ensure we don't make mistakes.

The source code from device app `verisigner` binary included under
`bins` can be found using the `verisigner-` tags in this repo.

The source code for the `signer-*` binaries is from:

https://github.com/tillitis/tkey-device-signer

Make reproducible builds of these binaries using the tag and building
with `TKEY_SIGNER_APP_NO_TOUCH=yes`.

To start using a new device app:

- Make sure there is a signed tag on the app's repo.
- Build it in a reproducible way (typically using the tkey-builder OCI
  image) with `TKEY_SIGNER_APP_NO_TOUCH=yes`.
- Copy the binary and the hash digest file to `internal/appbins/bins/`
  with matching names, like `signer-v1.0.1.bin` and the corresponding
  `signer-v1.0.1.bin.sha512`. They are built in during compile time
  and expects this exact name structure.
- Update the `README.md` in bins to document where this device app
  came from.

Then, if this app is meant to be used for TKey authentication:

- Set a new active device app for device authentication in the
  `remote-sign` configuration file by setting the new app's hash in
  `signingapphash`.

If the app is meant to be used for the Sigsum submit key, see below.

## Creating the Sigsum keys

The vendor's public keys are built into the `tkey-verification` and
`tkey-verify` binaries. Look for `SigsumConf` in
`internal/data/data.go`.

For each public key, provide, in this order:

- Name of the key.
- SSH public key corresponding to the private key of that particular
  device running the device app mentioned below.
- Tag of the app to run.
- SHA-512 digest of the device app binary.
- Start time of the key.
- End time.

Note that the device app *must* be known. See [Included device app
binaries](included-device-app-binaries).

A test vendor key is provided in `internal/data/data.go`. It contains
the default public key of our QEMU emulator, which is generated when
running verisigner v0.0.3.

If you want to use some other key(s), insert the vendor TKey you want
to use, then list the public key of the device app you want to use:

```
./tkey-verification show-pubkey --app internal/appbins/bins/signer-v1.0.1.bin
Public Key, app tag, and app hash for embedded vendor pubkeys follows on stdout:
03a7bd3be67cb466869904ec14b9974ebcc6e593abdc4151315ace2511b9c94d signer-v1.0.1 cd3c4f433f84648428113bd0a0cc407b2150e925a51b478006321e5a903c1638ce807138d1cc1f8f03cfb6236a87de0febde3ce0ddf177208e5483d1c169bac4
SSH version: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAOnvTvmfLRmhpkE7BS5l068xuWTq9xBUTFaziURuclN sigsum key
```

Enter the SSH key into `SigsumConf` in `internal/data/data.go`. Then
build everything.

To set this Sigsum key to be the active one used for vendor signing,
change the configuration file for `serve-signer` and change
`activekey`.

## Example verification and submit request files

- [Verification file](cmd/tkey-sigsum-submit/testdata/0001020304050607-ver-valid).
- [Submission file](cmd/tkey-sigsum-submit/testdata/0001020304050607-subm-valid).

## Releases of tkey-verification and reproducible builds

`tkey-verification` is released with the help of GoReleaser, see
`.goreleaser.yaml` in the root of the repo.

Currently this has to be done on a computer running macOS/Darwin, at
least for Tillitis' official releases. The reason is that `tkeyclient`
needs CGO enabled for Darwin to enumerate USB-devices, and that the
Darwin binary is signed with Tillitis' Apple Developer Certificate,
which at the moment also needs to be done using Darwin. We are looking
into solutions for both those points.

You should be able to build a binary that is a exact copy of our
release binaries if you use the same Go compiler, at least for the
statically linked Linux and Windows binaries.

Please see [the official
releases](https://github.com/tillitis/tkey-verification/releases) for
digests and details about the build environment.

Note that `tar.gz` and such files are not reproducible since they contain
a timestamp.

For the universal Darwin file, the signature produced by Tillitis
needs to be removed before it can be compared to one not built and
released by Tillitis. This can be done using ` codesign
--remove-signature path/to/binary`, at least on a Darwin machine.

The releases are published at
https://github.com/tillitis/tkey-verification/releases with the
binaries and checksum files.

Release v0.0.2-v0.0.3 were built with `make podman` and the
[release-builds](release-builds) directory contains digests of
released versions.

## Licenses and SPDX tags

Unless otherwise noted, the project sources are copyright Tillitis AB,
licensed under the terms and conditions of the "BSD-2-Clause" license.
See [LICENSE](LICENSE) for the full license text.

Until Nov 6, 2024, the license was GPL-2.0 Only.

Please note that this project embeds binaries that are released under
GPL-2.0 Only, see
[cmd/tkey-verification/bins/README.md](cmd/tkey-verification/bins/README.md)
for more details.

External source code we have imported are isolated in their own
directories. They may be released under other licenses. This is noted
with a similar `LICENSE` file in every directory containing imported
sources.

The project uses single-line references to Unique License Identifiers
as defined by the Linux Foundation's [SPDX project](https://spdx.org/)
on its own source files, but not necessarily imported files. The line
in each individual source file identifies the license applicable to
that file.

The current set of valid, predefined SPDX identifiers can be found on
the SPDX License List at:

https://spdx.org/licenses/

We attempt to follow the [REUSE
specification](https://reuse.software/).
