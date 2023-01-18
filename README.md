# Tillitis TKey Verification

**NOTE**: This is work in progress. We're not yet publishing
signatures for verification.

`tkey-verification` is a tool used for signing and verifying that a
TKey is genuine, produced by [Tillitis](https://tillitis.se/) (vendor)
and not tampered with.

## Procedure

### Terminology

- "signing server": An HSM-like machine providing signatures over
  messages and producing files to be uploaded later.
- "device under verification": The device the vendor is provisioning
  or the user is verifying.
- "device public key": The public key of the device under verification
  when running the signer application.
- "vendor signature": A signature made by the signing server.
- "device signature": A signature made on the device under
  verification with the signer application.

### Signing

`tkey-verification serve-signer` is run to provide a signing server on
a computer on the provisioning network with its own TKey, the vendor
key.

The device under verification is inserted into the provisioning
workstation.

`tkey-verification remote-sign` is run on the provisioning workstation
to retrieve the Unique Device Identifier (UDI), load the signer, ask
it for the device public key, and ask the signer to sign a random
challenge. We then verify the signature against the device public key
before proceeding.

After verifying we send the UDI and the public key to the signing
server, which will make the vendor signature.

The signing server signs the the device public key and outputs a file
in a directory `signatures/` which is named after the Unique Device
Identifier (in hex), for example `signatures/0133704100000015`, which
contains for example:

```
{
  "timestamp": "2023-01-12T12:04:24Z",
  "tag": "main",
  "signature": "a720d532e78c7f5aeb2ac61d9c112f6323cd9db1ce45d6ff6d727b05a38dabafab0087d2a9be770e1ce8e889178ea111a67bf366bb4af9d11e68a2dc229ffa0a"
}
```

Where the fields are:

- timestamp: RFC3339 UTC timestamp when the signature was done.
- tag: The Git tag of the ed25519 signer oracle used on the device
  under verification, `apps/signer/app.bin` compiled from [the apps
  repo](https://github.com/tillitis/tillitis-key1-apps/).
- signature: Vendor signature of the device public key. Stored in
  base16 (hex).

These files will later be published somewhere public, for example on a
web server. Note that the device public key isn't published but is
retrievable by anyone with access to the TKey.

### Verification

To verify a device, the user runs `tkey-verification verify`.

It first retrieves the Unique Device Identifier (UDI) from the TKey
under verification, then queries a web server for verification data
under a base URL (current default is "https://example.com/verify") +
UDI, for instance `0133704100000015`.

From the verification data we learn the tag of the signer-app that was
used when the verification was created, and the correct binary can
thus loaded onto the TKey. The device public key can then be extracted
from the TKey. We verify the vendor signature over the public key.
This proves that the vendor has signed the same device public key.

To check that the device under verification has the right private key
we now ask the signer to sign a random challenge, resulting in a
device signature. This signature should be able to be verified with
the already extracted device public key.

If the signature over the random message is verified this proves that
the TKey is in possession of the private key corresponding to the
already verified public key, thus proving that the TKey is genuine.

*Nota bene*: The same signer binary that was used for producing the
device signature during signing *must* be used when verifying it. If a
different signer is used then the device public key will not match
even if the TKey is the same. A verifier must check the "tag" field
and complain if it does not have a signer binary built from this tag.

We're currently thinking that we could provide binary releases of the
`tkey-verification` host program. The release will embed pre-built
signer binaries for all tags we ever used for verifications, as well
as the tag name to use for new verifications.

We want to be compatible with the sigsum transparency log and might
later post something on the log, perhaps just sha256(signature file
content).

https://git.glasklar.is/sigsum/project/documentation/-/blob/main/log.md#21-cryptography

#### Verification on a machine without network

If you're on a machine without network and need to verify a TKey you
can run `tkey-verification --show-url` which will output the URL to
the verification file.

Download this file (named after the TKey UDI in hex) on some networked
computer and transfer it back here. Given that the file is in current
working directory, you can now verify locally with: `tkey-verification
verify --from-file=.`

## Building and running

Currently, you have to build the signer-app binary yourself, and place
it in `internal/appbins/bins/TAG.bin` before building the tool.

1. Clone [https://github.com/tillitis-key1-apps](https://github.com/tillitis/tillitis-key1-apps).
   Alternatively, if you have a working Docker setup, you can try
   running:
   ```
   ./contrib/build-in-container.sh main
   ```

   Skip to 6) if that works out.

2. Just stay on the `main` branch.

3. Setup the build environment according to instructions in the README.

4. The signer-app needs to be built with the touch requirement
   removed. Run:
   ```
   make TKEY_SIGNER_APP_NO_TOUCH=yes -C apps signer/app.bin
   ```

5. Assuming the apps repository was cloned as a sibling to this repo, you
   can copy the binary of the ed25519 signer like:
   ```
   cp ../tillitis-key1-apps/apps/signer/app.bin ./internal/appbins/bins/main.bin
   ```

6. Build the `tkey-verification` tool with the signer-app tag to use
   when provisioning a verification using `remote-sign`, and the test
   file which contains public key(s) for vendor signing/verify. Also
   build CA, server, and client certs:

   ```
   % make DEVICE_SIGNERAPP_TAG=main SIGNING_PUBKEYS_FILE=test-vendor-signing-pubkeys.txt
   % make certs
   ```

   See below if you need to get hold of a different public key.

7. You now need 1 TKey and 1 QEMU machine running to try this out (or
   2 TKeys, or 2 QEMU machines, if you manage to get that working).
   One is Tillitis' (vendor's) signing TKey, and the other is a TKey
   that you want to sign and then verify as genuine. You need to know
   the serial port device paths for these.

8. Run the signing server on qemu (see below for details on how start,
   notice what device qemu said when starting):

   ```
   ./tkey-verification serve-signer --port /dev/pts/12
   ```

9. Insert the device under verification, the TKey to be signed and verified.

9. Get the signing server to sign for a device under verification
   (here a hardware TKey)

   ```
   % ./tkey-verification remote-sign
   ```

10. The signing server should now have signed and saved a verification
    file under `signatures` with a filename generated from the Unique
    Device Identifier, typically something like `0133704100000015`

11. Before trying to verify you need to remove and re-insert the
    device under verification to get it back to firmware mode.
    `tkey-verification` always requires to load the signer itself.
    Then try to verify:

    ```
    % ./tkey-verification verify
    Auto-detected serial port /dev/ttyACM0
    Connecting to device on serial port /dev/ttyACM0 ...
    Firmware name0:'tk1 ' name1:'mkdf' version:4
    Loading app...
    App loaded.
    App name0:'tk1 ' name1:'sign' version:1
    TKey UDI (BE): 0133704100000015
    TKey is genuine!
    ```

## Running qemu

You need [our fork of qemu](https://github.com/tillitis/qemu). Use the
"tk1" branch. You also need `firmware.elf` from [the main
repo](https://github.com/tillitis/tillitis-key1). Build the firmware
with: `cd hw/application_fpga;make firmware.elf`

Standing in the `hw/application_fpga` directory you can now start qemu:

```
% /path/to/qemu/build/qemu-system-riscv32 -nographic -M tk1,fifo=chrid -bios firmware.elf -chardev pty,id=chrid
```

## Creating the vendor public keys file

The vendor's public key is built into the tkey-verification binary
from a text file. Note that only 1 single public key is supported
currently.

For each public key, the tag of the signer-app binary used when
extracting the public key is also provided. The signing server needs
this so that its TKey can have the correct private key when signing.
Note that these tags per public key are independent and can differ
from the tag used for device signing.

A test file is provided in `test-vendor-signing-pubkeys.txt`. It
contains the default public key of our qemu machine.

If you want to use some other key(s) this is how:

If you're just testing start a qemu as a signing endpoint. See above.

Get the public key from the TKey in the signing server. We provide a
`show-pubkey` tool for that. The tag of the signer-app binary to use
must be given as an argument. The tool embeds signer-app binaries in
the same way as the `tkey-verification` tool.

An example using the tag "main" for this vendor public key, example
output:

```
% make show-pubkey
% ./show-pubkey --port /dev/pts/12 main
...
67b1464aa24f6593fe671ec100f30e858cdf7fbb0b4686bdf9ca47b5c648ba0f
```

Then enter the following in a file, for instance `other-pubkeys.txt`:
```
67b1464aa24f6593fe671ec100f30e858cdf7fbb0b4686bdf9ca47b5c648ba0f main
```

Then build everything with this file:

```
% make DEVICE_SIGNERAPP_TAG=main SIGNING_PUBKEYS_FILE=other-signing-pubkeys.txt
```
