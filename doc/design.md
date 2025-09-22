# Design of the TKey verification process

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
message, and verify that we signed a digest of it with the help of the
included Sigsum proof.

## Sigsum transparency log

We submit signed checksums of all identities in [a Sigsum transparency
log](https://sigsum.org/). We want to:

- Be able to monitor when our private key is used and signal to us if
  it's leaked.
- Increase trust in the identities by having our signatures logged and
  witnessed.
- Control that the submission of our signature was done at a time when
  our submit key was valid.

We don't store or publish the TKey identities, so we can't actually
verify the identities ourselves. See "Why is the TKey identity not
published?" below.

We plan to run a Sigsum monitor tailing the log to see when our key is
used. To make it easier to find illicit use of the key we will store
the *digest* of the TKey identity, but not the identity itself.

If the monitor finds our key has been used, it uses the digest
reported from the log and checks if this is indeed a known digest we
have signed. If not, it alerts us.

The timestamps by the witnesses should give us a hint when this was
first used. We can compare with the timestamps in our verification
files to see the last good verification file.

## Provisioning

Done by the vendor, maybe during provisioning of the FPGA bitstream,
but not necessarily.

- Create and [authenticate](#authenticate) a TKey identity, sign a
  hash digest of the identity and submit the signed digest to a Sigsum
  log.

- Publish the Sigsum proof and some metadata in a [verification
  file](#verification-file). Publish this on a web server indexed by
  the UDI, typically: https://tkey.tillitis.se/verify/UDI-in-hex

## Verification

Done by end user.

- Recreate and [authenticate](#authenticate) the TKey identity by
  loading the same app on the same TKey and doing a
  challenge/response.

- Verify that the TKey identity has been signed with a Sigsum proof.

All data needed to recreate and verify the identity is provided in the
[verification file](#verification-file).

## Verification file

The verification file contains:

- `timestamp`: RFC3339 timestamp when the signature was done.
- `apptag`: a human readable hint for anyone who wants to reproduce the
  procedure manually.
- `apphash`: hash digest for the specific device app to run.
- `proof`: Sigsum proof that this TKey identity is signed and logged.

In older versions of the verification file there is a vendor signature
instead of `proof`:

- `signature`: Ed25519 vendor's signature.

For compatibility with older TKeys we continue to support being able
to verify the vendor's signature. We identify what kind (proof or
signature) we need to use by the product ID of the TKey. Older TKeys:
require a signature, newer: require a Sigsum proof.

The canonical URL for this file in a TKey provisioned by Tillitis is:

https://tkey.tillitis.se/verify/UDI-in-hex

like:

https://tkey.tillitis.se/verify/0133704100000015

## Submit request file

The submit request file contains:

- `timestamp`: RFC3339 timestamp when the signature was done.
- `apptag`: a human readable hint for anyone who wants to reproduce the
  procedure manually.
- `apphash`: hash digest for the specific device app to run.
- `request`: sigsum add-leaf-request data.

## Authenticate

Both during provisioning and verification we need to authenticate the
TKey identity, to see that the combination of device app and hardware
is the expected.

- Load the signer device app.

- Retrieve its public key.

- Do a challenge/response, asking the running app to make a signature
  over some random data.

- Verify the signature with the already retrieved public key.

## What is verified?

What does verifying a TKey with `tkey-verify` prove?

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
(although compiled without touch requirement) publishing the signer
public key from this specific TKey would be equivalent of publishing
the user's public SSH key (if they choose not to use an USS and use
the signer without touch requirement) to the entire world. We were not
comfortable in doing that even if it would, in a way, be a way of
doing hardware attestation of the TKey. We might need to revisit this.

Note that we always recommend using an USS for all your own use of the
TKey! We also make it slightly hard to use a signer without touch
requirement for security reasons, but we see the usefulness of
providing it as an option for server use.

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
   Sigsum log [request file](#submit-request-file).
8. Publish the request file to the Sigsum monitor.
9. Submit the sigsum request included in the request file to the
   Sigsum log, collecting the proof.
10. Build the verification file, including the Sigsum proof.
11. Publish the [verification file](#verification-file), indexed by
    the UDI.
12. (Transfer the digest of the message to the future Sigsum monitor.)

The checksum of a TKey must be present at the monitor before
submitting the TKey identity to the log.

![Data flow during provisioning](../signing-procedure.svg)

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
