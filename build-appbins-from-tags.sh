#!/bin/sh -eu

# Tag to use from tillitis-key1-apps repo when building. This is overridden in
# a .deps-file, which along with the .sha512-file must be committed to the
# repo. This way we remember also which specific apps-repo tag a binary was
# built with.
appsrepotag="v0.0.6"

cd "${0%/*}"

tags="$(git ls-remote --tags origin | sed -n "s:.*/tags/\(verisigner-v[0-9]\{1,\}\.[0-9]\{1,\}\.[0-9]\{1,\}$\):\1:p")"

if [ -z "$tags" ]; then
  printf "no remote tags matching verisigner-vX.Y.Z\n"
  exit 1
fi

for tag in $tags; do
  # Skip building those that are ignored in internal/appbins/appbins.go
  [ "$tag" = "verisigner-v0.0.1" ] && continue
  [ "$tag" = "verisigner-v0.0.2" ] && continue
  ./build-appbin-in-container.sh "$tag" "$appsrepotag"
done
