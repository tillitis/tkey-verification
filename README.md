# Tillitis TKey Verification

`tkey-verification` is a tool used for signing a TKey identity and
verifying that it still has the same identity as it did when it was
produced by [Tillitis](https://tillitis.se/) (the vendor).

If you own a TKey and want make sure it's genuine you can follow
[these
instructions](https://tillitis.se/app/tkey-device-verification/) (on
Tillitis' web). Or just download a release of the tool right away:
https://github.com/tillitis/tkey-verification/releases

## Terminology

- "device under verification": The device the vendor is provisioning
  or the user is verifying.
- "device signature": A signature made on the device under
  verification with the signer device app.
- Unique Device Identifier (UDI): A unique identifier present in all
  TKeys. The 1st half identifies the revision of the hardware, the 2nd
  half is a serial number.
- "signing server": An HSM-like machine providing signatures over
  messages and producing files to be uploaded later.
- "signer": The device app verisigner (kept in this repository) or
  [tkey-device-signer](https://github.com/tillitis/tkey-device-signer).
- "signer public key": The public key of signer running on the device
  under verification.
- "vendor signature": A signature made by the signing server.

## Security Protocol

### During provisioning

1. Retrieve the UDI from the device under verification.
2. Run the signer with a specific tag on the device under
   verification. This creates a unique key pair.
3. Retrieve signer public key from the device under verification.
4. Ask signer to sign a random challenge.
5. Verify the signature of the random challenge with the retrieved
   public key to make sure signing works and the device proves that it
   has the corresponding private key.
6. Ask signer for a digest of the firmware binary (in ROM). Consult the
   internal firmware database to verify that the TKey, according to
   its hardware revision, is running the expected firmware.
7. Sign a message consisting of the UDI, firmware digest, and signer
   public key, with a vendor signature.
8. Publish the UDI, the tag of the signer program used, the hash
   digest of the binary of the same signer program, the vendor
   signature, and the timestamp when signature was made.

### Verifying

1. Retrieve the UDI from the device under verification.
2. Get the vendor signature and signer tag and digest for this UDI.
3. Run the signer with the same tag and hash on the device under
   verification.
4. Retrive the signer public key.
5. Ask signer to sign a random challenge.
6. Verify the signature of the random challenge with the signer public
   key thus proving that device under verification has access to the
   corresponding private key.
7. Ask signer for a hash digest of the firmware binary (in ROM).
   Consult the internal firmware database to verify that the TKey,
   according to its hardware revision, is running the expected
   firmware.
8. Recreate the message of UDI, firmware digest, signer public key.
   Verify the vendor signature of the message, thus proving that the
   UDI, the firmware, and this private/public key pair was the same
   during vendor signing.

Note that the exact same signer binary that was used for producing the
signer signature during provisioning *must* be used when verifying it.
If a different signer is used then the device public key will not
match even if the TKey is the same. A verifier must check the "tag"
and "hash" field and complain if it does not have a signer binary
built from this tag, and with the same hash.

## Building tkey-verification

A reproducible build should be able to be done with: `make podman`.
This requires a rootless podman setup.

XXX: Probably goreleaser to build for all archs.

The [release-builds](release-builds) directory contains checksums of
released versions (since we got reproducibility in place).

1. First get all app binaries built. The make command below runs a
   script which builds verisigner binaries from all tags named
   "verisigner-vX.Y.Z" and places them in
   `internal/appbins/bins/TAG.bin`. The scripts sets which tag of the
   tillitis-key1-apps repository to use by default. The script clones
   the repository inside a container, so the verisigner-tags need to
   have been pushed to the remote. Further details:

   - If a .bin.deps-file exists, its contents are used to set the
     apps-repo tag to use for the build, otherwise the file is created
     with the used default tag.
   - If a .bin.sha512-file is present, the built binary is verified
     against it, otherwise that file is created.
   - If the .bin-file already exists, it is directly verified using
     the .bin.sha512-file.

   ```
   make appbins-from-tags
   ```

   Note: the .deps- and .sha512-files are to be committed to the repo!

2. `tkey-verification` contains an in-code database mapping known
   hardware revisions (1st half of UDI) to their expected firmware
   size and hash. This needs to be maintained, in:
   [internal/firmwares/firmwares.go](internal/firmwares/firmwares.go)

3. Build the `tkey-verification` tool with the test file containing
   public key(s) for vendor signing/verify. Also build CA, server, and
   client certs:

   ```
   $ cp test-vendor-signing-pubkeys.txt cmd/tkey-verification/vendor-signing-pubkeys.txt
   $ make
   $ make certs
   ```

   The tag of the verisigner-app to run on the device under
   verification for signing was previously configured at build time.
   The app binary for this is now instead picked automatically by the
   tool. Among all embedded app binaries with tags matching
   "verisigner-vX.Y.Z", the one with the latest version number will be
   used for device signing. When developing this tool further, this
   may need to be side-stepped in code.

   See below if you need to get hold of a different public key.

   NOTE: for deploying the server part on a different machine (the
   default setup runs both serve-signer and remote-sign on localhost)
   you need to adjust the certificate generation in the
   [Makefile](Makefile).

## Building included device apps

The device apps used for signing is included in binary form under
`cmd/tkey-verification/bins/`.

Reproducible versions of the device app `verisigner` binary included
in this repo can be built from earlier tags. See the earlier tags and
instructions there.

The
[tkey-device-signer](https://github.com/tillitis/tkey-device-signer)
binary can be built reproducible from corresponding tags.

## Testing

-  You need 1 TKey and 1 QEMU machine running to try this out (or
   2 TKeys, or 2 QEMU machines, if you manage to get that working).
   One is Tillitis' (vendor's) signing TKey, and the other is a TKey
   that you want to sign and then verify as genuine. You need to know
   the serial port device paths for these.

-  Run the signing server on QEMU (see below for details on how to
   start, notice what device QEMU said when starting):

   ```
   ./tkey-verification serve-signer --config tkey-verification.yaml.example-serve-signer --port /dev/pts/12
   ```

- Insert the device under verification, the TKey to be signed and verified.

-  Get the signing server to sign for a device under verification
   (here a hardware TKey)

   ```
   $ ./tkey-verification remote-sign --config tkey-verification.yaml.example-remote-sign
   Auto-detected serial port /dev/ttyACM0
   Connecting to device on serial port /dev/ttyACM0 ...
   Firmware name0:'tk1 ' name1:'mkdf' version:4
   Loading verisigner-app built from tag:verisigner-v0.0.1 hash:9598910ec9ebe2504a5f894de6f8e067… ...
   App loaded.
   App name0:'veri' name1:'sign' version:1
   TKey UDI: 0x0001020304050607(BE) VendorID:0x0010 ProductID:8 ProductRev:3
   TKey firmware with size:3204 and verified hash:31accb1c40febc2bf02f48656a943336…
   Remote Sign was successful
   ```

- The signing server should now have signed and saved a verification
  file under `signatures` with a filename generated from the Unique
  Device Identifier, typically something like `0133704100000015`

- Before trying to verify you need to remove and re-insert the device
  under verification to get it back to firmware mode.
  `tkey-verification` always requires to load the signer itself. Then
  try to verify against local files in a directory using `verify -d
  signatures` (the default is to query a web server):

   ```
   $ ./tkey-verification verify -d signatures
   Auto-detected serial port /dev/ttyACM0
   Connecting to device on serial port /dev/ttyACM0 ...
   Firmware name0:'tk1 ' name1:'mkdf' version:4
   TKey UDI: 0x0001020304050607(BE) VendorID:0x0010 ProductID:8 ProductRev:3
   Reading signatures/0001020304050607 ...
   Auto-detected serial port /dev/ttyACM0
   Connecting to device on serial port /dev/ttyACM0 ...
   Firmware name0:'tk1 ' name1:'mkdf' version:4
   Loading verisigner-app built from tag:verisigner-v0.0.1 hash:9598910ec9ebe2504a5f894de6f8e067… ...
   App loaded.
   App name0:'veri' name1:'sign' version:1
   TKey firmware with size:3204 and verified hash:31accb1c40febc2bf02f48656a943336…
   TKey is genuine!
   ```

For more, see the manual page [tkey-verification(1)](system/tkey-verification.1).

## INcl
## Running QEMU

You need [our fork of QEMU](https://github.com/tillitis/qemu). Use the
"tk1" branch. You also need `firmware.elf` from [the main
repo](https://github.com/tillitis/tillitis-key1). Build the firmware
with: `cd hw/application_fpga;make firmware.elf`

Standing in the `hw/application_fpga` directory you can now start QEMU:

```
$ /path/to/qemu/build/qemu-system-riscv32 -nographic -M tk1,fifo=chrid -bios firmware.elf -chardev pty,id=chrid
```

## Creating the vendor public keys file

The vendor's public key is built into the tkey-verification binary
from a text file.

For each public key, the tag and hash digest of the device app used
when extracting the public key is also provided. The signing server
needs this so that its TKey can have the correct private key when
signing. Note that these tags per public key are independent from and
can be different from the tag used for device signing.

A test file is provided in `test-vendor-signing-pubkeys.txt`. It
contains the default public key of our QEMU machine, given most recent
verisigner-tag as of this writing.

If you want to use some other key(s) this is how:

If you're just testing start a QEMU as a signing endpoint. See above.

Get the public key from the TKey in the signing server. We provide a
`show-pubkey` tool for that. The tag of the verisigner-app binary to use
must be given as an argument. The tool embeds verisigner-app binaries in
the same way as the `tkey-verification` tool.

An example using the tag "main" for this vendor public key, example
output:

```
$ make show-pubkey
$ ./show-pubkey --port /dev/pts/12 verisigner-v0.0.1
...
038dd0b898c601517a09cd249d3c4f2de8e9aab38c5fa02701ae29bb41a6d863 verisigner-v0.0.1 9598910ec9ebe2504a5f894de6f8e0677dc94c156c7bd6f7e805a35354b3c85daa4ca66ab93f4d75221b501def457b4cafc933c6cdcf16d1eb8ccba6cccf6630
```
Enter that line into a file, for instance `other-pubkey.txt`. Then build everything with this file:

```
$ cat other-pubkey.txt >> vendor-signing-pubkeys.txt
$ make
```

## Signed metadata

The computer running `tkey-verification serve-sign` generates files
in a directory `signatures/` which is named after the Unique Device
Identifier (in hex), for example `signatures/0133704100000015`.

The file contains:

- timestamp: RFC3339 UTC timestamp when the signature was done.
- apptag: The Git tag of the verisigner program used on the device
  under verification,
- apphash: The hash of the verisigner program binary used on the
  device under verification. Stored in hexadecimal.
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

## Making releases of tkey-verification

Make the new release binaries for the expected version:

    ./make-release-builds 0.0.42

Generate and commit the new checksums:

    ./gen-release-checksums 0.0.42
    git add release-builds/*_0.0.42_*.sha512
    git commit -m "Release 0.0.42"

Then tag a new version and push it all:

    git tag -a v0.0.42 -m v0.0.42
    git push origin main v0.0.42

Publish the new release at
https://github.com/tillitis/tkey-verification/releases and upload the
binaries and checksum files. For MacOS we'll provide only the
universal binary.
