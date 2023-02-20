# Tillitis TKey Verification

**NOTE**: This is work in progress. We're not yet publishing
signatures for verification.

`tkey-verification` is a tool used for signing a TKey identity and
verifying that it still has the same identity as it did when it was
produced by [Tillitis](https://tillitis.se/) (the vendor).

## Terminology

- "device under verification": The device the vendor is provisioning
  or the user is verifying.
- "device signature": A signature made on the device under
  verification with the signer TKey program.
- Unique Device Identifier (UDI): A unique identifier present in all
  TKeys.
- "signing server": An HSM-like machine providing signatures over
  messages and producing files to be uploaded later.
- "signer": The TKey program signer from `apps/signer/app.bin`
  compiled from [the apps repo](https://github.com/tillitis/tillitis-key1-apps/).
- "signer public key": The public key of signer running on the device
  under verification.
- "vendor signature": A signature made by the signing server.

## Security Protocol

### During provisioning

1. Retrieve the UDI from the device under verification.
2. Run the signer with a specific tag on the device under verification
   thus creating a unique key pair.
3. Retrieve signer public key from the device under verification.
4. Ask signer to sign a random challenge.
5. Verify the signature of the random challenge with the retrieved
   public key to make sure signing works.
6. Sign the signer public key with a vendor signature.
7. Publish the UDI, the tag of the signer program used, and the vendor
   signature.

### Verifying

1. Retrieve the UDI from the device under verification.
2. Get the vendor signature and signer tag for this UDI.
3. Run the signer with the same tag on the device under verification.
4. Retrive the signer public key.
5. Ask signer to sign a random challenge.
6. Verify the signature of the random challenge with the signer public
   key thus proving that device under verification has access to the
   corresponding private key.
7. Verify the vendor signature of the signer public key thus proving
   that this private/public key pair was the same during vendor
   signing.

Note that the exact same signer binary that was used for producing the
signer signature during provisioning *must* be used when verifying it.
If a different signer is used then the device public key will not
match even if the TKey is the same. A verifier must check the "tag"
field and complain if it does not have a signer binary built from this
tag.

## Building and running

Currently, you have to build the signer-app binary yourself, and place
it in `internal/appbins/bins/TAG.bin` before building the tool.

1. Clone [https://github.com/tillitis-key1-apps](https://github.com/tillitis/tillitis-key1-apps).
   Alternatively, if you have a working podman setup, you can try
   running:
   ```
   ./contrib/build-in-container.sh main
   ```

   Skip to 6) if that works out.

2. Just stay on the `main` branch.

3. Setup the build environment according to instructions in the README.

4. The signer needs to be built with the touch requirement
   removed. Run:
   ```
   make TKEY_SIGNER_APP_NO_TOUCH=yes -C apps signer/app.bin
   ```

5. Assuming the apps repository was cloned as a sibling to this repo, you
   can copy the binary of the ed25519 signer like:
   ```
   cp ../tillitis-key1-apps/apps/signer/app.bin ./internal/appbins/bins/main.bin
   ```

6. Build the `tkey-verification` tool with the signer tag to use when
   provisioning a verification using `remote-sign`, and the test file
   which contains public key(s) for vendor signing/verify. Also build
   CA, server, and client certs:

   ```
   % make DEVICE_SIGNERAPP_TAG=main SIGNING_PUBKEYS_FILE=test-vendor-signing-pubkeys.txt
   % make certs
   ```

   See below if you need to get hold of a different public key.

   NOTE: for deploying the server part on a different machine (the
   default setup runs both serve-signer and remote-sign on localhost)
   you need to adjust the certificate generation in the
   [Makefile](Makefile).

7. You now need 1 TKey and 1 QEMU machine running to try this out (or
   2 TKeys, or 2 QEMU machines, if you manage to get that working).
   One is Tillitis' (vendor's) signing TKey, and the other is a TKey
   that you want to sign and then verify as genuine. You need to know
   the serial port device paths for these.

8. Run the signing server on qemu (see below for details on how start,
   notice what device qemu said when starting):

   ```
   ./tkey-verification serve-signer --config tkey-verification.yaml.example-serve-signer --port /dev/pts/12
   ```

9. Insert the device under verification, the TKey to be signed and verified.

9. Get the signing server to sign for a device under verification
   (here a hardware TKey)

   ```
   % ./tkey-verification remote-sign --config tkey-verification.yaml.example-remote-sign
   ```

10. The signing server should now have signed and saved a verification
    file under `signatures` with a filename generated from the Unique
    Device Identifier, typically something like `0133704100000015`

11. Before trying to verify you need to remove and re-insert the
    device under verification to get it back to firmware mode.
    `tkey-verification` always requires to load the signer itself.
    Then try to verify against local files in a directory (`verify -d
    signatures`, the default is to query a web server):

    ```
    % ./tkey-verification verify -d signatures
    Auto-detected serial port /dev/ttyACM0
    Connecting to device on serial port /dev/ttyACM0 ...
    Firmware name0:'tk1 ' name1:'mkdf' version:4
    Loading app...
    App loaded.
    App name0:'tk1 ' name1:'sign' version:1
    TKey UDI (BE): 0133704100000015
    TKey is genuine!
    ```

For more, see the manual page [tkey-verification(1)](system/tkey-verification.1).


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

## Signed metadata

The computer running `tkey-verification serve-sign` generates files
in a directory `signatures/` which is named after the Unique Device
Identifier (in hex), for example `signatures/0133704100000015`.

The file contains:

- timestamp: RFC3339 UTC timestamp when the signature was done.
- tag: The Git tag of the signer program used on the device under verification,
- signature: Vendor signature of the device public key. Stored in hexadecimal.

Example file content:

```
{
  "timestamp": "2023-01-12T12:04:24Z",
  "tag": "v0.0.4",
  "signature": "a720d532e78c7f5aeb2ac61d9c112f6323cd9db1ce45d6ff6d727b05a38dabafab0087d2a9be770e1ce8e889178ea111a67bf366bb4af9d11e68a2dc229ffa0a"
}
```
