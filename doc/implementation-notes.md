# Implementation notes

## Assets

There are some compiled-in assets:

- application binaries: The device apps used for both vendor signing
  and device signatures.
- vendor public keys: The public key extracted from a vendor TKey
  during vendor signing and used for verification. Might be several,
  including historical keys no longer being used for vendor signing.
- known firmwares: Expected firmwares for all provisioned TKeys.

Commands are responsible for initializing their own assets. For
instance, `verify` needs all three, but `remote-sign` and
`serve-signer` need only two, and `show-pubkey` needs none.

### Application binaries

Initialized by calling `appbins.go:NewAppBins()`.

Actual binaries are located in the `bins` directory stored like this:

- `name-tag`, like `signer-v1.0.1.bin`: the actual device app binary.
- `name-tag.sha512`, like `signer-v1.0.1.bin.sha512`: the SHA-512
  digest of the above file to help ensure we don't make mistakes.

### Vendor public keys

Initialized by calling `vendorpubkeys.go:NewVendorKeys()`. Needs to
know the appbins (see above).

The actual vendor keys are defined in the text file
`vendor-signing-pubkeys.txt`, which is embedded in the binary at build
time and parsed at start. It contains:

- the public key
- the name and tag of the device app to use for vendor signing.
- the hash digest of that device app.

Example content:

```
50d9a125f51d85ffa1fb12011bdae05d39e03cda2a35d0daf3077072daabbb10 verisigner-v0.0.3 f8ecdcda53a296636a0297c250b27fb649860645626cc8ad935eabb4c43ea3e1841c40300544fade4189aa4143c1ca8fe82361e3d874b42b0e2404793a170142
```

In use, it's initialized like this:

```go
appBins, err := NewAppBins()
vendorKeys, err := NewVendorKeys()
```

### Known firmwares

Initialized by calling `firmwares.go:NewFirmwares()`.

It's used by probing a TKey for UDI, then looking up a firmware for a
specific UDI with `GetFirmware(udi)`. Now you know the size and the
SHA-512 digest of the expected firmware and call the device app to ask
it for a digest.

## `serve-signer` command

Defined in `servesigner.go`.

- Initialises its assets using `NewAppBins()` and `NewVendorKeys()`.

- Connects to a vendor TKey, loads the built-in vendor signing device
  app indicated by the configuration in `vendorapphash`.

- Sets up a HTTPS server exposing a simple API through "net/rpc". The
  RPC commands are in `api.go`.

- Waits for commands.

- When a `Sign` command appears it requests the device app to sign the
  message and returns an OK or error. It writes the signature over the
  message and some metadata under the signatures directory. Note that
  it doesn't store the message itself. A verifier needs to recreate
  the message themselves from their TKey.

- Goes back to wait for more commands.

## `remote-sign` command

Defined in `remotesign.go`.

- Sets up its assets using `NewAppBins()` and `NewFirmwares()`.

- Connects to a TKey during provisioning and loads built-in device app
  indicated by the configuration in `signingapphash`.

- Extracts the public key.

- Verifies that firmware digest is as expected.

- Verifies that the TKey can sign a random challenge, proving that it
  has the corresponding private key.

- Builds a message to be signed.

- Asks the server (same program but started with `serve-signer`) to
  sign the message.

## `verify` command

Defined in `verify.go`.

- Initialises its assets by using `NewAppBins()`, `NewVendorKeys()`,
  and `NewFirmwares()`.

- Connects to a TKey, request UDI.

- If this is `verify --show-url` we just construct the URL from the
  UDI, outputs that and exits.

- Otherwise, we fetch the verification data from something like
  `https://tkey.tillitis.se/verify/0133708100000002`.

- Look up the necessary device app to load from our embedded assets
  and load it.

- Extract the public key.

- Look up the expected firmware hash digest from the UDI.

- Compare the firmware digest of the TKey compared to the expected.

- Recreate the message seen during provisioning.

- Verify vendor's signature over the message against any of the
  vendor's known public keys.

- Sign and verify a random challenge, proving that the TKey knows the
  corresponding private key.

## `show-pubkey` command

Defined in `showpubkey.go`.

- Connects to a TKey.

- Reads the device app file, on the path passed to it in `--app`.

- Computes the SHA-512 digest of the file.

- Loads the app device.

- Extracts the public key.

- Prints the public key, the name-tag, and the app digest.
