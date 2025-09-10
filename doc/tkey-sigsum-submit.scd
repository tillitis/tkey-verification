tkey-sigsum-submit(1)

# NAME

tkey-sigsum-submit - Process TKey submission files by submitting
requests to a Sigsum log.

# SYNOPSIS

*tkey-sigsum-submit* -h/--help

*tkey-sigsum-submit* -m directory -n directory -d directory

# DESCRIPTION

*tkey-sigsum-submit* processes TKey submissions files and generates
TKey verification files that can be used to verify a TKey identity.

Each submission file contains a Sigsum request. The request is used to
submit to a Sigsum log. The result is a verification file.

# OPTIONS

*-m* | *--submissions-dir* directory

	Set directory to read submission files from.

*-n* | *--processed-submissions-dir* directory

	Set directory to move submitted files to.

*-d* | *--verifications-dir* directory

	Set directory to write generated verification files in.

# EXAMPLES

```
$ tkey-sigsum-submit -m signatures -n processed -d verifications
2025/09/10 10:23:23 [INFO] Attempting to submit checksum#1 to log: https://test.sigsum.org/barreleye
2025/09/10 10:23:23 [INFO] Attempting to retrieve proof for checksum#1
```

# FILES

The files in the submission directory (set with *-m*) are produced by
*tkey-verification*(1) running the *serve-sign* command.

After a succesful run of *tkey-sigsum-submit* the submitted submission
files are moved from the submissions directory to the processed
submissions directory (*-n*). The generated verification files are
placed in the verification directory (*-d*).

# SEE ALSO

*tkey-verification*(1) *tkey-verify*(1)

# AUTHORS

Tillitis AB, https://tillitis.se/
