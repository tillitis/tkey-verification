#!/bin/sh -eu

# Tag to use from tillitis-key1-apps repo when building. This is overridden in
# a .deps-file, which along with the .sha512-file must be committed to the
# repo. This way we remember also which specific apps-repo tag a binary was
# built with.

# TODO adjust this once apps-repo integration branch is merged to main and tagged.
appsrepotag="for-verisigner-v0.0.2"

cd "${0%/*}"

# TODO could skip building those that are ignored by
# internal/appbins/appbins.go
tags="$(git ls-remote --tags origin | sed -n "s,.*/tags/\(verisigner-v[0-9]\+\.[0-9]\+\.[0-9]\+$\),\1,p")"

if [ -z "$tags" ]; then
  printf "no remote tags matching verisigner-vX.Y.Z\n"
  exit 1
fi

for tag in $tags; do
  ./build-appbin-in-container.sh "$tag" "$appsrepotag"
done
