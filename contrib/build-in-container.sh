#!/bin/sh -eu

tag="${1?pass a tag/branch to build from}"

cd "${0%/*}"

crun=docker
cname="tkey-build"

$crun run -it --name "$cname" \
      --mount type=bind,source="$(pwd)/containerbuild",target=/containerbuild \
      ghcr.io/tillitis/tkey-builder \
      /bin/bash /containerbuild "$tag"

# Copy to expected locations
$crun cp "$cname":/tillitis-key1-apps/apps/signer/app.bin ../cmd/tkey-verification/app.bin

$crun rm "$cname"

ls -l ../cmd/tkey-verification/app.bin
sha256sum ../cmd/tkey-verification/app.bin
