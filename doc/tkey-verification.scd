tkey-verification(1)

# NAME

A program to sign or verify the identity of a Tillitis TKey.

# SYNOPSIS

*tkey-verification* -h/--help

*tkey-verification* remote-sign [--port port]

*tkey-verification* serve-signer [--config path] [--check-config] [--port port]

*tkey-verification* show-pubkey [--port port]

*tkey-verification* verify [--base-url url] [-d | --base-dir] [--port port] [-u | --show-url]

# DESCRIPTION

*tkey-verification* is a program to sign or verify the identity of a
Tillitis TKey.

A typical end user will only be interested in the *verify* command.

The commands are as follows:

*remote-sign*

	Request that the tkey-verification serve-signer sign the identity
	of a TKey.

	To use, first insert a TKey and then run the command. If one is
	already running a TKey program, remove it and re-insert before
	running the command.

	Options:

	*--port* port

		Path to the TKey device port. If not given, autodetection will be
		attempted.

*serve-signer*

	Provide a signing server with its own TKey, the vendor key.

	When it receives a signing request it signs the data and creates a new
	file with metadata and a signature. See FILES.

	Options:

	*--config* path

		Path to the configuration file.

	*--check-config*

		Check if the configuration file is OK and exit.

	*--port* port

		Path to the TKey device port. If not given, autodetection will be
		attempted.

*show-pubkey*

	Output public key data to populate "vendor-signing-pubkeys.txt"
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

*verify*

	Verify a TKey identity.

	To use, first insert a TKey and then run the command. If one is
	already running a TKey program, remove it and re-insert before running
	the command.

	Options:

	*--base-url* url

		Set the base URL of verification server for fetching verification
		data. Default is "https://example.com/verify".

	*-d* | *--base-dir* directory

		Read verification data from a file located in directory
		and named after the TKey Unique Device Identifier in hex, instead of
		from a URL.

	*--port* port

		Path to the TKey device port. If not given, autodetection will be
		attempted.

	*-u* | *--show-url*

		Only output the URL to the verification data that should be
		downloaded, then exit.

## Verification on a machine without network

If you're on a machine without network and need to verify a TKey you
can run

```
$ tkey-verification verify ---show-url
```

which will output the URL to the verification file. Download the file
using another, networked, computer and somehow bring the file or type
it in again on your airgapped computer. Then run:

```
tkey-verification verify -d=.
```

to read from the current directory.

# FILES

*tkey-verification* serve-signer produces a file which is named after
the Unique Device Identifier (in hexadecimal) for every signature
made. An example filename would be "signatures/0133704100000015".

The file contains:

- timestamp: RFC3339 UTC timestamp when the signature was done.
- tag: The Git tag of the signer program used on the device under
  verification,
- signature: Vendor ed25519 signature of the device public key. Stored
  in hexadecimal.

The files generated will later be published on a public web server.
The publication is out of scope for the current program.

*tkey-verification* show-pubkey generates output for a file called
"vendor-signing-pubkeys.txt" to be included in the build of a new
*tkey-verification*. It's output is:

- Ed25519 public key
- app name and tag.
- digest of hash

Example file:

```
038dd0b898c601517a09cd249d3c4f2de8e9aab38c5fa02701ae29bb41a6d863 verisigner-v0.0.1 9598910ec9ebe2504a5f894de6f8e0677dc94c156c7bd6f7e805a35354b3c85daa4ca66ab93f4d75221b501def457b4cafc933c6cdcf16d1eb8ccba6cccf6630
```

# EXAMPLES

Verifying the identity of a Tillitis TKey using a networked computer.

```
$ tkey-verification verify
```

Verifying the identity with a non-networked computer: First

```
$ tkey-verification --show-url
```

Then download the file and move it to your current working directory.
Keep the name of the file intact since it's named after the TKey
Unique Device Identifier. and run:

```
$ tkey-verification verify -d=.
```

In order to include a new vendor signing key, use:

```
% ./tkey-verification show-pubkey --port /dev/pts/12 --app cmd/tkey-verification/bins/signer-v1.0.0.bin
Connecting to device on serial port /dev/pts/12 ...
Firmware name0:'tk1 ' name1:'mkdf' version:5
Public Key, app tag, and app hash for vendor-signing-pubkeys.txt follows on stdout:
038dd0b898c601517a09cd249d3c4f2de8e9aab38c5fa02701ae29bb41a6d863 verisigner-v0.0.1 9598910ec9ebe2504a5f894de6f8e0677dc94c156c7bd6f7e805a35354b3c85daa4ca66ab93f4d75221b501def457b4cafc933c6cdcf16d1eb8ccba6cccf6630
```

# AUTHORS

Tillitis AB, https://tillitis.se/

# CAVEATS

You can currently not use several TKeys on the same computer at the
same time, which means you can't use *serve-signer* and the other
commands on the same computer.

# SECURITY CONSIDERATIONS

*tkey-verification* only verifies the /identity/ of the TKey hasn't
changed since signing by the vendor. It might have been manipulated in
other ways.

The device public key isn't published in the files generated by the
*serve-signer* but is retrievable by anyone with access to the device
under verification.

You probably shouldn't expose the computers running *serve-signer* or
*remote-sign* on the Internet.
