# Tillitis TKey Verification

`tkey-verification` is a tool used for signing a TKey identity and
verifying that the same TKey still has the same identity later.

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

You can download a release of the tool at:

https://github.com/tillitis/tkey-verification/releases

Or do:

```
$ go install github.com/tillitis/tkey-verification/cmd/tkey-verification@latest
```

Please note that if you install with `go install` you won't get the
tag in `--version`.

## Usage

For the typical end user with network access, insert the TKey and run:

```
$ tkey-verification verify
```

For more advanced use and for provisioning, see the man page in
`doc/tkey-verification.1`.

## Introduction

Think of a TKey identity as a message made up of:

- Unique Device Identifier (UDI)
- the public key of a signing device app, typically
  [signer](https://github.com/tillitis/tkey-device-signer), running on
  the TKey
- digest of the firmware of this TKey

This identity is what we want to prove is the same to the end user. We
do this by signing a digest of the identity, logging the digest into a
transparency log, and publishing a [verification
file](verification-file) about it.

The user can later download the verification file, recreate the
message, and verify that we signed a digest of it with the included
Sigsum proof.

## Sigsum transparency log

We submit signed checksums of all identities in [a Sigsum transparency
log](https://sigsum.org/). We want to:

- Be able to monitor when our private key is used and signal to us if
  it's leaked.
- Increase trust in the identities by having our signatures logged and
  witnessed.

We don't store or publish the TKey identities, so we can't actually
verify the identities ourselves. See "Why is the TKey identity not
published?" below.

We plan to run a Sigsum monitor tailing the log to see when our key is
used. To make it easier to find illicit use of the key we will store
the *digest* of the TKey identity, but not the identity itself.

If the monitor finds our key has been used, it uses the digest
reported from the log and checks if this is indeed a digest we have
signed. If not, it alerts us.

The timestamps by the witnesses should give us a hint when this was
first used. We can compare with the timestamps in our verification
files to see the last good verification file.

## Provisioning

Done by the vendor, maybe during provisioning of the FPGA bitstream,
but not necessarily.

- Create and [check](#check-identity) a TKey identity, sign a hash
  digest of the identity and submit the signed digest to a Sigsum log.

- Publish the Sigsum proof and some metadata, a [verification
  file](#verification-file), reachable by HTTP, indexed by the UDI,
  typically: https://tkey.tillitis.se/UDI-in-hex

## Verification

Done by end user.

- Recreate and [check](#check-identity) the TKey identity by loading
  the same app on the same TKey and doing a challenge/response.

- Verify the TKey identity with a Sigsum proof.

All data needed to recreate and verify the identity is provided in the
[verification file](#verification-file).

## Verification file

The verification file contains:

- `timestamp`: RFC3339 timestamp when the signature was done.
- `apptag`: a human readable hint for anyone who wants to reproduce the
  procedure manually.
- `apphash`: hash digest for the specific device app to run.
- `proof`: Sigsum proof that this TKey identity is signed and logged.

In older versions of the verification file, instead of `proof`:

- `signature`: Ed25519 vendor's signature.

For compatibility with older TKeys we continue to support being able
to verify the vendor's signature. We identify what kind (proof or
signature) we need to use by the product ID of the TKey. Older TKeys:
require a signature, newer: require a Sigsum proof.

The canonical URL for this file in a TKey provisioned by Tillitis is:

https://tkey.tillitis.se/verify/UDI-in-hex

like:

https://tkey.tillitis.se/verify/0133704100000015

## Check identity

Both during provisioning and verification we need to authenticate the
TKey identity, to see that the combination of device app and hardware
is the expected.

- Load the signer device app.

- Retrieve its public key.

- Do a challenge/response, asking the running app to make a signature
  over some random data.

- Verify the signature with the already retrieved public key.

## What is verified?

What does verifying a TKey with `tkey-verification verify` prove?

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

- Provisioning: The vendor signs a message containing the Unique
  Device Identifier (UDI), a digest over the observed firmware, and
  the signer's public key.

  The message itself is not published, but the signature and some
  metadata is (see [Verification file](#verification-file) for
  details). The message can later be recreated by the verification
  process.

- Verification: `tkey-verification` first recreates the message (UDI,
  firmware digest, signer's public key), checks the vendor's
  signature over the message, and finally does a challenge/response to
  prove that the device has the corresponding private key.

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
- The rest of the FPGA design isn't proven either, except the UDS, but
  at least it worked as expected with the loaded signer app.

Not proved at all:

- USB controller CH552 firmware and hardware.
- PCB design.

## Why is the TKey identity not published?

The TKey identity that is signed by the vendor's key is not published.
It is, instead, recreated when verifying a TKey. This makes it
impossible for anyone else, including the vendor, to verify the
message if they haven't stored the message somewhere else.

When originally designing this system we were afraid that publishing,
or even keeping, the signer public key in a way that ties it very
strongly to a certain UDI would be bad for the user.

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
- The distribution of the vendor's public key is sensitive. Since
  all trust is placed in the vendor's signature, all fails if the
  end user is tricked to use the wrong public key. It's right now
  embedded in tkey-verification.
- The distribution of the tkey-verification client app is sensitive,
  since if it is malicious it can just say "TKey is genuine!" without
  actually doing much else.

  However, the build of tkey-verification is reproducible if using
  pinned versions of tools (but currently not the macOS binary). The
  same verification can also be done independently by other tools.

## Security Protocol

Detailed step-by-step security protocol.

### Terminology

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
- "vendor's public key": The public key of the vendor, typically
  Tillitis or an IT department, corresponding to a private key in a
  TKey in the signing server.
- "vendor's Sigsum private key": The private key the vendor uses to
  sign a digest for logging in the Sigsum transparency log.
- "vendor's Sigsum public key": The public key corresponding to the
  vendor's Sigsum private key.
- "vendor's signature": A signature made by the signing server.

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
7. Sign a digest of a message consisting of the UDI, firmware digest,
   and signer public key with vendor's private Sigsum key, creating a
   Sigsum log request file.
8. Submit the request file to the Sigsum log, collecting the proof.
9. Build the verification file, including the Sigsum proof.
10. Publish the [verification file](#verification-file), indexed by
    the UDI.
11. (Transfer the digest of the message to the future Sigsum monitor.)

The following diagram contains an overview of how data flows during
provisioning at Tillitis:

![Data flow during provisioning](signing-procedure.svg)

### Verifying

1. Retrieve the UDI from the device under verification.
2. Get the [verification file](#verification-file) with the Sigsum
   proof, app tag, and app digest for this UDI.
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
9. Verify the Sigsum proof of the message, thus proving that the
   UDI, the firmware, and this private/public key pair was the same
   during vendor's signing.

Note that the exact same signer binary that was used for producing the
signer signature during provisioning *must* be used when verifying it.
If a different signer is used then the device private/public key will
not match, even if the TKey is the same. A verifier must check the
"hash" field and complain if it does not have a signer binary with the
same digest.

## Building tkey-verification

Build the `tkey-verification` tool with the test file containing the
vendor's public key(s).

```
$ cp test-vendor-signing-pubkeys.txt internal/vendorkey/vendor-signing-pubkeys.txt
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

- The signing server should now have signed and saved a submit request
  file under `signatures` with a filename generated from the Unique
  Device Identifier, typically something like `0133704100000015` if
  from Tillitis, but `0001020304050607` if the bitstream has been
  built directly from
  [tillitis-key1](https://github.com/tillitis/tillitis-key1).

- To submit the TKey Identity using the submit request file. First
  create two empty directories to hold the processed submit request
  file and the generated verification file. Then run
  `tkey-sigsum-submit`:

  ```
  $ mkdir processed-submissions
  $ mkdir verifications
  $ ./tkey-sigsum-submit -m signatures -n processed-submissions/ -d verifications/
  2025/05/04 12:04:34 [INFO] Attempting to submit checksum#1 to log: https://test.sigsum.org/barreleye
  2025/05/04 12:04:35 [INFO] Attempting to retrieve proof for checksum#1
  ```

- Before trying to verify you need to remove and re-insert the device
  under verification to get it back to firmware mode.
  `tkey-verification` always requires to load the signer itself. Then
  try to verify against local files in a directory using `verify -d
  signatures` (the default is to query a web server):

  ```
  $ ./tkey-verification verify -d verifications
  TKey UDI: 0x0001020304050607(BE) VendorID: 0x0010 ProductID: 8 ProductRev: 3
  Reading verification data from file verifications/0001020304050607 ...
  TKey is genuine!
  ```

For the complete set of commands, see the manual page
[tkey-verification(1)](doc/tkey-verification.1).

## Creating the vendor's public keys file

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

## Example verification file

```
{
  "timestamp": "2023-03-03T09:31:51Z",
  "apptag": "verisigner-v0.0.1",
  "apphash": "9598910ec9ebe2504a5f894de6f8e0677dc94c156c7bd6f7e805a35354b3c85daa4ca66ab93f4d75221b501def457b4cafc933c6cdcf16d1eb8ccba6cccf6630",
  "proof": "  "proof": "version=1\nlog=4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d\nleaf=1b6d f3744a4d05231ceed5d704e7fcdd8ee436f2253d980cf5716ae34cc16c06f439 55b94e42482923adf99d49bc5b3aa3b96093139817284ced6403167d47db0fa3091d8282adea6a1e11ebe3f1f42bf76ddceb8b3f0bbec4dd96f8f6908760bd0e\n\nsize=4186\nroot_hash=be8491d96283e89afb0014b82be85ba70cccb9e672fdbf595f701fb456e46cd0\nsignature=880584e76411f6ac7d2d7f85166b320cd08d6a775cf9b78969ff185dc2b6410c34e4ac2d3aa78d64285ab2a3259177b787da0d5326b71d034c6a7471a9dc5e0d\ncosignature=70b861a010f25030de6ff6a5267e0b951e70c04b20ba4a3ce41e7fba7b9b7dfc 1755522370 8f4507b9e9076ebab7f9234108de5e3b0bc1836a4933c0ac69ad338461537c8d6a0fcf93d2b7dc2416fbcd73c6b19dd3d2a311313920d7191a2ee7591cb73c04\ncosignature=b95ef35a9ffb3cf516f423a04128d37d3bffc74d4096bd5e967990c53d09678a 1755522370 4970b9b159c3e723ed11c5a75b70be027d5d4ba51e66209263ac779d52ce93ac9a1a3d798551274df0ffb05ea5e82e929fb3ece062fba676515f851d1f6bf005\ncosignature=0d4f46a219ab309cea48cde9712e7d8486fc99802f873175eeab70fb84b4f5a4 1755522370 65bc6e601f91d1faf81ec5a6aa7b24d11b89bcd1ea9e570c0a122c236bda7058500f2dc5706b16fa6853145922835034f561197e7d03156ddfe070d58aa7c40c\ncosignature=49c4cd6124b7c572f3354d854d50b2a4b057a750f786cf03103c09de339c4ea3 1755522370 b57f4ee89b3b0f39303e72fa7359afd696abaa759d9e255788355bb420607522c5b5cbde72ce6943b67e029858cf795609b2ff726dd11c61edfa37bfef323d07\ncosignature=42351ad474b29c04187fd0c8c7670656386f323f02e9a4ef0a0055ec061ecac8 1755522370 9c16d95c617a97f2da89b1d594510950725a0d537ddd5e76eac5d5ef87de9ea9b2d249467c2a4c078cff6edbf87ecc25b08b6b5cbfecb42efb5439408d75930f\ncosignature=1c997261f16e6e81d13f420900a2542a4b6a049c2d996324ee5d82a90ca3360c 1755522370 fe82dc7e0f051492be67b9ebce4fe6c3b488e3286e10f55363655c6391a132eb8c645ec7a4e414a81c6b2d8d149331bdb1e4bdd5609ff79009174d76f17c4302\n\nleaf_index=4185\nnode_hash=9364bfbdef749709839140a812c628abf7f6b9a324d748056c8661b283f4a427\nnode_hash=e6d3a8151cdff24f78931465cfe5f9083080b18d86831a0e8f581c16061af439\nnode_hash=d8cf3ff208c18ddc4f3b21acb70f9ac12c14989a6372a4bb8602596423bed265\nnode_hash=9a062feda65100c4b5cfbc4297e9a07af77565b53fd77719ab75b8d31107f247\nnode_hash=9ca6b461d616cf790a32a967574087298abb4cd0c3da938b7fed143b7d92b5ec\n"
}
```

Unescaped Sigsum proof from above:

```
version=1
log=4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d
leaf=37a7 f3744a4d05231ceed5d704e7fcdd8ee436f2253d980cf5716ae34cc16c06f439 b7cde475555105f6d638d9b9c23b0e66f377a649c2ccbb0cf345adaecb91bbd99ea2193d02739c184c016917d94eff0432c74af94923f676032eab32a5d5fa0f

size=4062
root_hash=49978d3adbc02ec2236b14cd144f66cc9af9ab425805a5d94d0b841b97aefcb7
signature=6e9bfaf3d510e7a633581d0d32779544e24d2fa9613623646bb840612b67988214e3e320ad4e718c909bd184659d084dd80139245af831c1667f40c22df0a40b
cosignature=1c997261f16e6e81d13f420900a2542a4b6a049c2d996324ee5d82a90ca3360c 1755093398 929d20560672440355d20c4ec8100cfc68a3b7b03d3b4d28c9035be20a878ed56840aa7f09c02e12a7ffc750b38079533de30838d3692c86839e22e7ee854e02
cosignature=70b861a010f25030de6ff6a5267e0b951e70c04b20ba4a3ce41e7fba7b9b7dfc 1755093398 1fb1d21df1c86bc715e755e1a7ec202d96f1cd50532a4ba2a05bcdf4ee63da9d38222481e1bc87460b149a6f422adba2bdd2df1a37f5d693c7415b1f7ad89b0b
cosignature=b95ef35a9ffb3cf516f423a04128d37d3bffc74d4096bd5e967990c53d09678a 1755093398 79b6296cb16ff0f7c91a8bfdc01f6e21071dbb3b28147c7ffe0a836f3efe5c3362a3276d4b115556be18bd94d53d530e944a48fa3f47baccefe39bdd8d1aa50c
cosignature=0d4f46a219ab309cea48cde9712e7d8486fc99802f873175eeab70fb84b4f5a4 1755093398 ccb980e1288afb9b5d5af638747659ac6e38158311a33e4ea5beae5970b24a4a02271d31311ae3f151a7d670febd485298a0f1c27b2d6da7f65da7237a0ef30b
cosignature=49c4cd6124b7c572f3354d854d50b2a4b057a750f786cf03103c09de339c4ea3 1755093398 f43e218c43190614a4ad55607cd90bcbbdff4ddb03479a36d97e2e7110adb1b884da58ff0cb79cef34521af5e7d275550669b05e4f720b66409d7948d97da00b
cosignature=42351ad474b29c04187fd0c8c7670656386f323f02e9a4ef0a0055ec061ecac8 1755093398 a1b99033b4c25c6928f1fe1f01139293b2ebe60389b666ebf70ce50a9f0482cb5430122f44428696cd627db53c6d3a3c47ce71d6bee837cca3f73d0eca01320f

leaf_index=4060
node_hash=8134a4b1064781ea4bcd2d1d52a55b28e1487135428efd796adf06e6d00dabb8
node_hash=bbbe78c97a3239921223a28ad37fa32797b7bec3341d1c73f256b9b357ded247
node_hash=c2a794d933464b45857d384f5b35856e52c5e6848313aacffc59b58e6d5401e9
node_hash=0c39cd314a79e8448420ac0f34b0d40df7fdfdba17fe361c9064a64ff8412a8e
node_hash=3122831be7d8ba0ec99668c54738b8179e9b2c38f2fdf90e0c976c37c188f59c
node_hash=c6d62d0782909d3bca2d24c6cb9d7a79402c08f197fdf752da734b40aa9147ad
node_hash=669f4a51ce90d6277f63228b31bf329bc4a302501353d4d8b1089615c6f28afb
node_hash=50626559da5d62f538bb83a268b6e1c9207a084c3ec6505faed00b2ca166392e
node_hash=f677460b20097baf3117a02e92cfad2ac951a43b213088f7494ba1fe7775b204
node_hash=c83420a707810b251a145f460d4cb6191fd68910d68190a8685b7ce9bf4d5c5a
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

## Open questions

- Can we use the exact same key pair as the Sigsum submit key as we
  used as a vendor's key pair before? If not, why not?

- Can we continue not to publish the TKey identity? See [Why is the
  signed message not
  published?](#why-is-the-signed-message-not-published). Is this even
  a good idea?

- Decide on the format of the proof in the verification file. Included
  as an JSON-escaped string like in the example included here? As a
  separate resource on another URL linked through the JSON file?

- Should the timestamp when the signature was done be included in the
  signed message? In the older design it was unprotected.

- What do we do with all the older signatures? Keep them unlogged? If
  we want to Sigsum log them we need to do it some other way than the
  proposed new system, since we can't recreate the TKey identities and
  sign them.
