tkey-verification(1)

# NAME

A program to verify the identity of a Tillitis TKey.

# SYNOPSIS

*tkey-verify* -h/--help

*tkey-verify* [--base-url url] [-d | --base-dir] [--port port] [-u | --show-url] [--speed speed]

# DESCRIPTION

*tkey-verify* is a program to verify the identity of a Tillitis TKey.

To use, first insert a TKey and then run the command. If one is
already running a TKey program, remove it and re-insert before running
the program.

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

*--speed* speed

	Speed in bit/s of the TKey device port.

## Verification on a machine without network

If you're on a machine without network and need to verify a TKey you
can run

```
$ tkey-verify ---show-url
```

which will output the URL to the verification file. Download the file
using another, networked, computer and somehow bring the file or type
it in again on your airgapped computer. Then run:

```
tkey-verify -d=.
```

to read from the current directory.

# EXAMPLES

Verifying the identity of a Tillitis TKey using a networked computer.

```
$ tkey-verify
TKey UDI: 0x0133708100000002(BE) VendorID: 0x1337 ProductID: 2 ProductRev: 1
TKey is genuine!
```

Verifying the identity with a non-networked computer: First

```
$ tkey-verify --show-url
```

Then download the file and move it to your current working directory.
Keep the name of the file intact since it's named after the TKey
Unique Device Identifier. Then run:

```
$ tkey-verify -d=.
TKey UDI: 0x0133708100000002(BE) VendorID: 0x1337 ProductID: 2 ProductRev: 1
Reading verification data from file ./0133708100000002 ...
TKey is genuine!
```

# AUTHORS

Tillitis AB, https://tillitis.se/

# SECURITY CONSIDERATIONS

*tkey-verify* only verifies the /identity/ of the TKey hasn't changed
since signing by the vendor. It might have been manipulated in other
ways.

The device public key isn't published in the verification files but is
retrievable by anyone with access to the device under verification.
