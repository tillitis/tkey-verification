#!/bin/sh -eu

pubkeysfile="${1:-}"
signerapptag="${2:-}"

if [ -z "$pubkeysfile" ]; then
  printf "SIGNING_PUBKEYS_FILE is not set\n"
  exit 1
fi

if [ -z "$signerapptag" ]; then
  printf "DEVICE_SIGNERAPP_TAG is not set\n"
  exit 1
fi

cut <"$pubkeysfile" -f 2 -d " " \
 | while read -r tag; do
     appbin="internal/appbins/bins/$tag.bin"
     if [ ! -e "$appbin" ]; then
       printf "%s is missing, referenced in $pubkeysfile\n" "$appbin"
       exit 1
     fi
   done

appbin="internal/appbins/bins/$signerapptag.bin"
if [ ! -e "$appbin" ]; then
  printf "%s is missing, referenced in DEVICE_SIGNERAPP_TAG\n" "$appbin"
  exit 1
fi
