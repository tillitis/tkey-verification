#!/bin/sh -eu

tag="${1?pass a tag/branch to build from}"

cd "${0%/*}"

cname="tkey-build"

podman run -it --name "$cname" \
       --mount type=bind,source="$(pwd)",target=/contrib \
       ghcr.io/tillitis/tkey-builder \
       /bin/bash /contrib/containerbuild "$tag"

dest="../internal/appbins/bins/$tag.bin"

podman cp "$cname":/tillitis-key1-apps/apps/signer/app.bin "$dest"

podman rm "$cname"

ls -l "$dest"
sha256sum "$dest"
