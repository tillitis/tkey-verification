#!/bin/sh -eu

tag="${1?pass a tag/branch to build from}"

cd "${0%/*}"

crun=docker
cname="tkey-build"

$crun run -it --name "$cname" \
      --mount type=bind,source="$(pwd)/containerbuild",target=/containerbuild \
      ghcr.io/tillitis/tkey-builder \
      /bin/bash /containerbuild "$tag"

dest="../internal/appbins/bins/"$tag".bin"

$crun cp "$cname":/tillitis-key1-apps/apps/signer/app.bin "$dest"

$crun rm "$cname"

ls -l "$dest"
sha256sum "$dest"
