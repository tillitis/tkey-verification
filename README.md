
NOTE: This is work in progress. We're not yet publishing signatures
for verification.

This repository contains the `tkey-verification` tool, used for
verifying that a TKey is genuine, produced by Tillitis (vendor) and
not tampered with. The repository also contain documentation for the
tool as well as the verification process.

`tkey-verification sign` is first run to create a unique hash (H) for
a specific TKey. It then uses Tillitis' (the vendor's) signing
private-key to create a signature (S) over the hash. The signature
should then be published somewhere public, so that it can be retrieved
by a user using the hash as a (key-value) key. For example as plain
files on a web server. The program currently outputs a file in a
directory `signatures/` which is named after the hash (in hex), and
containing the signature (also hex).

```
H = hash(udi,pubkey)
S = signature(H)
T = the signer-app binary that was running on the TKey when making H
    was built from this Git tag
```

The same signer-app binary that was used for producing the signature
*must* be used when verifying it. If a different signer-app is used
then the hashes will not match even if the TKey is the same.
Therefore, the tag (T) used when signing needs to be shipped along
with the physical TKey. This could be on paper, but perhaps also
elsewhere in case the paper is lost.

`tkey-verification verify` is then run. It first creates the TKey hash
(H) in the same manner, and then retrieve the corresponding signature
(S). Currently by looking for the file in `signatures/`. If the
signature can be verified using Tillitis' (the vendor's) signing
public-key, then the TKey is genuine.

We're currently thinking that we could provide binary releases of the
`tkey-verification` host program. The version number of this program
will be the same as the tag of the signer-app binary that it embeds.
This way the correct host program can be picked for verification,
according to the paper accompanying the TKey. This is still TODO, and
currently we just build the signer-app from main.

We want to be compatible with sigsum. Same kind of hash and signature:
SHA256 and Ed25519.
https://git.glasklar.is/sigsum/project/documentation/-/blob/main/log.md#21-cryptography

We use base16 (hex) to encode binary data.

The repository contains a test-signing ed25519 keypair that is used
for sign/verify, as well as a tool `gen-signing-keypair` for
generating such keypair.

# Building and running

Currently, you have to build the signer-app binary yourself, and place
it in `cmd/tkey-verification/app.bin` before building the tool.

1. Clone [https://github.com/tillitis-key1-apps](https://github.com/tillitis/tillitis-key1-apps). Alternatively, if you
   have a working Docker setup, you can try running
   `./contrib/build-in-container main`. Skip to 6) if that works out.
2. Just stay on the `main` branch.
3. Setup the build environment according to instructions in the README.
4. You can build just the app with: `make -C apps signer/app.bin`
5. Assuming the apps repository was cloned as a sibling to this repo, you
   can move back to this repo and copy the binary like:
   ```
   cp ../tillitis-key1-apps/apps/signer/app.bin ./cmd/tkey-verification/app.bin
   ```
6. Build the `tkey-verification` tool with `make`.
7. Plug in a TKey.
8. Create the signed verification file: `./tkey-verification sign`
9. Re-plug the TKey (the tool *must* load the app itself!)
10. Run the verification: `./tkey-verification verify`.
