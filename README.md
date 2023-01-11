# Tillitis TKey Verification

**NOTE**: This is work in progress. We're not yet publishing
signatures for verification.

`tkey-verification` is a tool used for signing and verifying that a
TKey is genuine, produced by [Tillitis](https://tillitis.se/) (vendor)
and not tampered with.

## Procedure

### Signing

`tkey-verification serve-signer` is run to provide a signing service
on a computer on the provisioning network with its own TKey.

The TKey is inserted into the provisioning workstation.

`tkey-verification remote-sign` is run on the provisioning workstation
to create a unique hash for a specific TKey (hash = sha256(udi,pubkey)
and sign it with our vendor key by calling the signing service above.

`tkey-verification remote-sign` currently outputs a file in a
directory `signatures/` which is named after the Unique Device
Identifier (in hex), so something like `signatures/0133704100000015`
and contains something like:

```
{
  "timestamp": 1673366672,
  "tag": "main",
  "signature": "8256ec5fdf7b497fd8430e9e4217e2733080af93061b7dc13976fffadfad42724881db52e12e1dae32f85a13732a78a808ec15cd21d9a5cf195d10237c695601"
}
```

Where the fields are:

- timestamp: seconds since the Unix epoch when the signature was done.
- tag: The Git tag of the ed25519 signer oracle used on the device
  under verification, `apps/signer/app.bin` in the apps repo.
- signature: Vendor's ed25519 signature of the TKey's hash in base16
  (hex).

These files will later be published somewhere public, for example on a
web server.

### Verification

To verify a device, the user runs `tkey-verification verify`. It first
retrieves the Unique Device Identifier (UDI), then runs the signer on
the TKey and retrieves the public key and produces a unique hash, hash
= sha256(udi, pubkey).

`tkey-verification verify` then looks for a file under the
`signatures/` directory named after its UDI, for example
`signatures/0133704100000015`. If the signature can be verified using
Tillitis' (the vendor's) signing public key, then the TKey is genuine.

*Nota bene*: The same signer binary that was used for producing the
public key during signing *must* be used when verifying it. If a
different signer is used then the hashes will not match even if the
TKey is the same. A verifier must check the "tag" field and complain
if its own version of the signer doesn't come from the same tag.

We're currently thinking that we could provide binary releases of the
`tkey-verification` host program. The version number of this program
will be the same as the tag of the signer binary that it embeds. This
way the `tkey-verification` program itself will know if the tags
differs in the `signature` file and can complain that you need to run
another version. This is still TODO, and currently we just build the
signer from main.

We want to be compatible with sigsum. Same kind of hash and signature:
SHA256 and Ed25519.
https://git.glasklar.is/sigsum/project/documentation/-/blob/main/log.md#21-cryptography

## Building and running

Currently, you have to build the signer-app binary yourself, and place
it in `cmd/tkey-verification/app.bin` before building the tool.

1. Clone [https://github.com/tillitis-key1-apps](https://github.com/tillitis/tillitis-key1-apps).
   Alternatively, if you have a working Docker setup, you can try
   running:
   ```
   ./contrib/build-in-container main
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
   cp ../tillitis-key1-apps/apps/signer/app.bin ./cmd/tkey-verification/app.bin
   ```

6. Build the `tkey-verification` tool with the test public key, and
   also CA, server, and client certs:
   
   ```
   % make SIGNING_PUBKEY=test-signing-tkey.pub
   % make certs
   ```

   See below if you need to get hold of a different public key.

7. You now need 1 TKey and 1 QEMU machine running to try this out (or
   2 TKeys, or 2 QEMU machines, if you manage to get that working).
   One is Tillitis' (vendor's) signing TKey, and the other is a TKey
   that you want to sign and then verify as genuine. You need to know
   the serial port device paths for these.

8. Run the signing endpoint on qemu (see below for details on how
   start, notice what device qemu said when starting):

   ```
   ./tkey-verification serve-signer --port /dev/pts/12
   ```

9. Insert the TKey to be signed and verified.

9. Get the signing endpoint to sign for a TKey (here a hardware TKey)

   ```
   % ./tkey-verification remote-sign
   ```

10. The signing endpoint should now have signed and saved a
    verification file under `signatures` with a filename generated
    from the Unique Device Identifier, typically something like
    `0133704100000015`

11. Before trying to verify you need to remove and re-insert the TKey
    under verification to get it back to firmware mode.
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
    TKey raw UDI: 0133704100000015
    Verified signature over matching hash, TKey is genuine!
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

## Getting the vendor public key

The vendor public key is built into the tkey-verification binary.
A test public key is in `test-signing-tkey.pub`.

If you want to use some other key this is how you get it:

If you're just testing start a qemu as a signing endpoint. See above.
   

Get the public key from the signing endpoint, for instance by running
`tkey-runapp` and `tkey-sign` from the
[tillitis-key1-apps](https://github.com/tillitis/tillitis-key1-apps)
repo.
   
```
% ./tkey-runapp --port /dev/pts/12 apps/signer/app.bin 
 
% ./tkey-sign --port /dev/pts/12 apps/app.lds
Connecting to TKey on serial port /dev/pts/12 ...
Public Key from TKey:  67b1464aa24f6593fe671ec100f30e858cdf7fbb0b4686bdf9ca47b5c648ba0f 
```

Copy
"67b1464aa24f6593fe671ec100f30e858cdf7fbb0b4686bdf9ca47b5c648ba0f"
to a file, for instance `other-signing-tkey.pub`.

Then build everything with this public key:

```
make SIGNING_PUBKEY=other-signing-tkey.pub
```
