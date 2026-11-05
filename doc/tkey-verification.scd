tkey-verification(1)

# NAME

tkey-verification - sign the identity of a Tillitis TKey.

# SYNOPSIS

*tkey-verification* -h/--help

*tkey-verification* sign

*tkey-verification* show-pubkey [--port port] [--speed speed] --app path

# DESCRIPTION

*tkey-verification* cryptographically signs an assertion about the
identity of a Tillitis TKey and produces a Sigsum log request for it.
It is meant to be used with *tkey-sigsum-submit*(1) which will submit
the requests to a Sigsum transparency log and produce a verification
file.

A typical end user will only be interested in the corresponding
*tkey-verify*(1) command. *tkey-verification* is for the vendor.

The commands are as follows:

*sign*

	Automatically detect and sign a TKey using another TKey as the
	vendor key.

	The device port is autodected.

*show-pubkey*

	Output public key data to populate the embedded vendor pubkeys
	for building into *tkey-verification* to be able to use some other
	commands. This is necessary in order to bootstrap *tkey-verification*
	from scratch or to add a new vendor signing key.

	The output includes public key, app tag, and app hash in the
	right format for the file.

	Use the *--app* to specify the path of the app to load.

	Options:

	*--app* path

		Load app in *path* into TKey.

	*--port* port

		Path to the TKey device port. If not given, autodetection will be
		attempted.

	*--speed* speed

		Speed in bit/s of the TKey device port.

# FILES

*sign* has a YAML configuration file. The default name is `tkey-verification.yaml`.

```
---
# SHA-512 digest of device app for device authentication of new device.
# This is tag signer-tkey-verification-2
authappdigest: "fd1bb113cad8373d3fef85ffbc5ff4bd2714fa471b2aa1c4cc8f707f61adb1157eda501fa46035545c256664f0f0ae3da2c56aa85dda9b99d6beebc41baadf6f"

# Sigsum submit public key
activekey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILr61E/1ABXtB+gsEcGpn6kIQk9XxJwUpf5npZak3A8m sigsum key"

# USB serial of TKey used for Sigsum submission
activeserial: "8e7473ea-e464-45a4-8096-2e61ed0a748e"
```

The *sign* command produces a submission file which is named after the
Unique Device Identifier (in hexadecimal) for every signature made. An
example filename would be "signatures/0133704100000015".

The file contains:

- timestamp: RFC3339 UTC timestamp when the signature was done.
- tag: The Git tag of the signer program used on the device under
  verification,
- request: A Sigsum request to log a digest of our message.

The files generated can be submitted to a Sigsum log with
*tkey-sigsum-submit*(1).

# EXAMPLES

Run the signing server with a vendor key TKey inserted:

```
$ tkey-verification serve-signer --config tkey-verification-server.yaml
```

On the provisioning computer, insert the new TKey and run:

```
$ tkey-verification remote-sign --config tkey-verification-client.yaml
```

In order to include a new vendor signing key and Sigsum submit key, use:

```
$ tkey-verification show-pubkey --app internal/appbins/bins/signer-v1.0.1.bin
Public Key, app tag, and app hash for embedded vendor pubkeys follows on stdout:
03a7bd3be67cb466869904ec14b9974ebcc6e593abdc4151315ace2511b9c94d signer-v1.0.1 cd3c4f433f84648428113bd0a0cc407b2150e925a51b478006321e5a903c1638ce807138d1cc1f8f03cfb6236a87de0febde3ce0ddf177208e5483d1c169bac4
SSH version: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAOnvTvmfLRmhpkE7BS5l068xuWTq9xBUTFaziURuclN sigsum key
```

## SEE ALSO

*tkey-sigsum-submit*(1) *tkey-verify*(1)

# AUTHORS

Tillitis AB, https://tillitis.se/

# SECURITY CONSIDERATIONS

You probably shouldn't expose a computers meant for running
*tkey-verification* on the Internet.
