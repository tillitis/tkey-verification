tkey-verification(1)

# NAME

tkey-verification - sign the identity of a Tillitis TKey.

# SYNOPSIS

*tkey-verification* -h/--help

*tkey-verification* remote-sign [--port port] [--speed speed]

*tkey-verification* serve-signer [--config path] [--check-config] [--port
port] [--speed speed]

*tkey-verification* show-pubkey [--port port] [--speed speed] --app path

# DESCRIPTION

*tkey-verification* signs the identity of a Tillitis TKey.

A typical end user will only be interested in the *tkey-verify*(1)
command. *tkey-verification* is for the vendor.

The commands are as follows:

*remote-sign*

	Request that the *tkey-verification* serve-signer sign the identity
	of a TKey.

	To use, first insert a TKey and then run the command.

	Options:

	*--port* port

		Path to the TKey device port. If not given, autodetection will be
		attempted.

	*--speed* speed

		Speed in bit/s of the TKey device port.

*serve-signer*

	Provide a signing server with its own TKey, the vendor key.

	When it receives a signing request from *remote-sign* it signs the
	message and creates a new file with metadata and a Sigsum log
	request. See FILES.

	Options:

	*--config* path

		Path to the configuration file.

	*--check-config*

		Check if the configuration file is OK and exit.

	*--port* port

		Path to the TKey device port. If not given, autodetection will be
		attempted.

	*--speed* speed

		Speed in bit/s of the TKey device port.

*show-pubkey*

	Output public key data to populate the embedded vendor pubkeys
	for building into *tkey-verification* to be able to use some other
	commands. This is necessary in order to bootstrap *tkey-verification*
	from scratch or to add another vendor signing key.

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

*tkey-verification* serve-signer produces a submission file which is
named after the Unique Device Identifier (in hexadecimal) for every
signature made. An example filename would be
"signatures/0133704100000015".

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

# CAVEATS

You can currently not use several TKeys on the same computer at the
same time, which means you can't use *serve-signer* and the other
commands on the same computer, unless you start them with *--port*.

# SECURITY CONSIDERATIONS

You probably shouldn't expose the computers running *serve-signer* or
*remote-sign* on the Internet.
