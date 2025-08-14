# Tillitis TKey Verification

`tkey-verification` is a tool used for signing a TKey identity and
verifying that the same TKey still has the same identity later.

The verification of this identity does not prove that the TKey hasn't
been tampered with, only that the identity of an app running on it is
the same and, to a lesser degree, that it still runs the same
firmware.

*Note well*: If your TKey hasn't been provisioned by Tillitis, for
example your IT department, you will need to run their version of the
`tkey-verification` program instead of this one.

## Installation

[Official
instructions](https://www.tillitis.se/applications/tkey-device-verification/)
on Tillitis' web.

You can download a release of the tool at:

  https://github.com/tillitis/tkey-verification/releases

Or do:

```
$ go install github.com/tillitis/tkey-verification/cmd/tkey-verification@latest
```

if you have a Go compiler. Please note that if you install like this
you won't get the tag in `--version`.

## Terminology

- "device under verification": The device the vendor is provisioning
  or the user is verifying.
- "device signature": A signature made on the device under
  verification with the signer device app.
- Unique Device Identifier (UDI): A unique identifier present in all
  TKeys. The 1st half identifies the revision of the hardware, the 2nd
  half is a serial number.
- "signing server": An HSM-like machine providing signatures over
  messages and producing files to be uploaded to some database.
- "signer": A device app used for confirming the TKey's identity,
  right now either verisigner (source in older versions in this
  repository, look for verisigner tags) or
  [tkey-device-signer](https://github.com/tillitis/tkey-device-signer).
- "signer public key": The public key of signer running on the device
  under verification.
- "vendor public key": The public key of the vendor, typically
  Tillitis, corresponding to a private key in a TKey in the signing
  server.
- "vendor signature": A signature made by the signing server.

## What is verified?

What does verifying a TKey with `tkey-verification` prove?

To explain the verification and what it proves, first we need a brief
explanation on how the TKey works. The TKey uses measured boot. The
measured boot guarantees that every app that starts on the TKey gets a
unique identity called the Compound Device Identity (CDI).

The CDI is a combination of:

- a per-device unique secret embedded in the hardware, the Unique
  Device Secret (UDS),
  
- the integrity of the software before it is started, as measured by
  immutable and thefore trusted firmware, and,

- an optional User Supplied Secret (not used in this case).

The CDI is computed like this:

```
CDI = blake2s(UDS, blake2s(application), USS)
```

where `blake2s` is the hash function BLAKE2s from [RFC
7693](https://www.rfc-editor.org/info/rfc7693).

There are two parts to verifying a TKey. First what the vendor does
during provisioning, then what the user does during verification:

- Provisioning: The vendor signes a message containing the Unique
  Device Identifier (UDI), a digest over the observed firmware, and
  the signer's public key.

  The message itself is not published, but the signature and some
  metadata is (see [Verification file](#verification-file) for
  details). The message can later be recreated by the verification
  process.

- Verification: `tkey-verification` first recreates the message (UDI,
  firmware digest, signer's public key), checks the vendor signature
  over the message, and finally does a challenge/response to prove
  that the device under verification has the corresponding private
  key.

**Proven**: It's now proven that the currently used TKey device,
running this device app is the same as the TKey device (or at least a
device with the exact same UDS) that was running the same device app
during provisioning.

Less strongly shown:

- The firmware check assumes that a hash digest over the part of
  memory where the firmware is supposed to be suffices. In a
  manipulated TKey the real firmware might be somewhere else, with a
  copy of the expected firmware in the right place in the memory map.
- The authenticity of the RISC-V softcore isn't proven, but it was at
  least able to run the device app successfully.
- The rest of the FPGA design, except the UDS, but at least it worked
  as expected with the loaded signer app.

Not proved at all:

- USB controller CH552 firmware and hardware.
- PCB design.

## Why is the signed message not published?

The message that is signed by the vendor key is not published. It is,
instead, recreated when verifying a TKey. This makes it impossible for
anyone else to verify the message, including for the vendor, if the
vendor haven't stored the message somewhere else.

When designing this system we were afraid that publishing, or even
keeping, the signer public key in a way that ties it very strongly to
a certain UDI would be bad for the user. 

Since we're currently using the ordinary
[signer](https://github.com/tillitis/tkey-device-signer) device app
publishing the signer public key from this specific TKey would be
equivalent of publishing the user's public SSH key (if they choose not
to use an USS) to the entire world. We were not comfortable in doing
that even if it would, in a way, be a way of doing hardware
attestation of the TKey. We might need to revisit this.

Note that we always recommend using an USS for all your own use of the
TKey!

## Weaknesses

- The entire device is not proven.
- The distribution of the vendor public key is sensitive. Since all
  trust is placed in the vendor's signature, all fails if the end user
  is tricked to use the wrong vendor public key. It's right now
  embedded in tkey-verification.
- The distribution of the tkey-verification client app is sensitive,
  since if it is malicious it can just say "TKey is genuine!" without
  actually doing much else.

  However, the build of tkey-verification is reproducible if using
  pinned versions of tools (but currently not the macOS binary). The
  same verification can also be done independently by other tools.

## Security Protocol

### During provisioning

1. Retrieve the UDI from the device under verification.
2. Run the signer with a specific tag on the device under
   verification. This creates a unique key pair.
3. Retrieve signer public key from the device under verification.
4. Ask signer to sign a random challenge.
5. Verify the signature of the random challenge with the retrieved
   public key to let the device prove that it has the corresponding
   private key.
6. Ask signer for a digest of the firmware binary (in ROM). Consult
   the internal firmware database to verify that the TKey, according
   to its hardware revision, is running the expected firmware.
7. Sign a message consisting of the UDI, firmware digest, and signer
   public key with a vendor signature.
8. Publish the [Verification file](#verification-file) containing the
   tag and digest of the signer program used, the vendor signature,
   and the timestamp when signature was made. This should be indexed
   by the UDI.

### Verifying

1. Retrieve the UDI from the device under verification.
2. Get the [Verification file](#verification-file) with the vendor
   signature, signer tag and digest for this UDI.
3. Run the signer with the same tag and digest on the device under
   verification.
4. Retrieve the signer public key.
5. Ask signer to sign a random challenge.
6. Verify the signature of the random challenge with the signer public
   key thus proving that the device under verification has access to the
   corresponding private key.
7. Ask signer for a digest of the firmware binary (in ROM). Consult
   the internal firmware database to verify that the TKey, according
   to its hardware revision, is running the expected firmware.
8. Recreate the message of UDI, firmware digest and signer public key.
9. Verify the vendor signature of the message, thus proving that the
   UDI, the firmware, and this private/public key pair was the same
   during vendor signing.

Note that the exact same signer binary that was used for producing the
signer signature during provisioning *must* be used when verifying it.
If a different signer is used then the device private/public key will
not match, even if the TKey is the same. A verifier must check the
"hash" field and complain if it does not have a signer binary with the
same digest.

## Building tkey-verification

Build the `tkey-verification` tool with the test file containing
public key(s) for vendor signing/verify.

```
$ cp test-vendor-signing-pubkeys.txt cmd/tkey-verification/vendor-signing-pubkeys.txt
$ make
```

See below if you need to get hold of a different public key.

The device apps used for signing is included in binary form under
`cmd/tkey-verification/bins/`. See more info under [Building included
device apps](#building-included-device-apps) if you want to build them
yourself.

## Maintenance

See [Implementation notes](doc/implementation-notes.md) for more
in-depth notes on the program.

- `tkey-verification` contains an in-code database mapping known
  hardware revisions (first half of the Unique Device Identifier) to
  their expected firmware size and hash. This needs to be maintained
  in
  [cmd/tkey-verification/firmwares.go](cmd/tkey-verification/firmwares.go)
  in `NewFirmwares()`.

## Building included device apps

The device apps used for signing is included in binary form under
`cmd/tkey-verification/bins/`.

Reproducible versions of the device app `verisigner` binary included
in this repo can be built from earlier verisigner tags. Checkout the
wanted tag and follow the instructions there.

The [signer](https://github.com/tillitis/tkey-device-signer) binary
can be built reproducible from the tags mentioned in the `bins`
directory. Please note that you have to build without touch
requirement.

## Certificates

For your convenience we include a test CA and some test certificates
in `certs`. They expire 10 years after being generated.

If you need to rebuild CA, server, and client certs you can use any
ordinary X.509 certificate tools like GnuTLS's certtool or OpenSSL to
generate your certificates.

You can also install the small [certstrap
tool](https://github.com/square/certstrap) and run:

```
$ make certs
```

## Testing

- You need 1 TKey and 1 QEMU machine running to try this out (or 2
  TKeys, or 2 QEMU machines, if you manage to get that working). One
  is Tillitis' (vendor's) signing TKey, and the other is a TKey that
  you want to sign and then verify as genuine. You need to know the
  serial port device paths for these.

- Run the signing server on QEMU (see [the Tillitis Developer
  Handbook](https://dev.tillitis.se/tools/#qemu-emulator) for more
  information on how to run QEMU). Notice the port QEMU provides when
  starting.

  ```
  ./tkey-verification serve-signer --config tkey-verification.yaml.example-serve-signer --port /dev/pts/12
  ```

- Insert the device under verification, the TKey to be signed and verified.

- Get the signing server to sign for a device under verification (here
  a hardware TKey)

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

- The signing server should now have signed and saved a verification
  file under `signatures` with a filename generated from the Unique
  Device Identifier, typically something like `0133704100000015` if
  from Tillitis, but `0001020304050607` if the bitstream has been
  built directly from
  [tillitis-key1](https://github.com/tillitis/tillitis-key1).

- Before trying to verify you need to remove and re-insert the device
  under verification to get it back to firmware mode.
  `tkey-verification` always requires to load the signer itself. Then
  try to verify against local files in a directory using `verify -d
  signatures` (the default is to query a web server):

  ```
  $ ./tkey-verification verify -d signatures
  TKey UDI: 0x0001020304050607(BE) VendorID: 0x0010 ProductID: 8 ProductRev: 3
  Reading verification data from file signatures/0001020304050607 ...
  TKey is genuine!
  ```

For the complete set of commands, see the manual page
[tkey-verification(1)](doc/tkey-verification.1).

## Creating the vendor public keys file

The vendor's public key is built into the tkey-verification binary
from a text file.

For each public key, the tag and hash digest of the device app used
when extracting the public key is also provided. The signing server
needs this so that its TKey can have the correct private key when
signing. Note that these tags per public key are independent from and
can be different from the tag used for device signing.

A test file is provided in `test-vendor-signing-pubkeys.txt`. It
contains the default public key of our QEMU machine, which is
generated when running verisigner v0.0.3.

If you want to use some other key(s) this is how:

If you're just testing start a QEMU as a signing endpoint. See above.

Get the public key from the TKey in the signing server. We provide a
command in `tkey-verification`, `show-pubkey`, for that. The path to
the app binary to use must be given as an argument.

Example:

```
./tkey-verification show-pubkey --port /dev/pts/10 --app cmd/tkey-verification/bins/signer-v1.0.1.bin
Public Key, app tag, and app hash for vendor-signing-pubkeys.txt follows on stdout:
03a7bd3be67cb466869904ec14b9974ebcc6e593abdc4151315ace2511b9c94d signer-v1.0.1 cd3c4f433f84648428113bd0a0cc407b2150e925a51b478006321e5a903c1638ce807138d1cc1f8f03cfb6236a87de0febde3ce0ddf177208e5483d1c169bac4
```

Enter that line into a file, for instance `other-pubkey.txt`. Then build everything with this file:

```
$ cat other-pubkey.txt >> cmd/tkey-verification/vendor-signing-pubkeys.txt
$ make
```

## Verification file

The computer running `tkey-verification serve-sign` generates files
in a directory `signatures/` which is named after the Unique Device
Identifier (in hex), for example `signatures/0133704100000015`. This
file is needed in order to be able to verify a TKey.

The file contains:

- timestamp: RFC3339 UTC timestamp when the signature was done.
- apptag: The Git tag of the signer app used on the device under
  verification,
- apphash: The hash of the signer app binary used on the device under
  verification. Stored in hexadecimal.
- signature: Vendor signature of the message (described above). Stored
  in hexadecimal.

Example file content:

```
{
  "timestamp": "2023-03-03T09:31:51Z",
  "apptag": "verisigner-v0.0.1",
  "apphash": "9598910ec9ebe2504a5f894de6f8e0677dc94c156c7bd6f7e805a35354b3c85daa4ca66ab93f4d75221b501def457b4cafc933c6cdcf16d1eb8ccba6cccf6630",
  "signature": "db4e7a72b720b33f6d4887df0f9dcdd6988ca8adb6b0042d8e8c92b5be3e4e39d908f166d093f3ab20880102d43a2b0c8e31178ab7cdb59977dcf7204116cc0c"
}
```

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
