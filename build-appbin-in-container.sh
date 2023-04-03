#!/bin/sh -eu

tag="${1?pass a verisigner-tag to build from (tkey-verification repo)}"
appsrepotag="${2?pass the tag in tillitis-key1-apps repo to use}"

cd "${0%/*}"

destd="internal/appbins/bins"
destf="$tag.bin"

if ! hash sha512sum; then
  sha512sum() {
    shasum -a 512 "$@"
  }
fi

if [ -e "$destd/$destf" ]; then
  cd "$destd"
  printf "%s already exists.\n" "$destf"
  if [ ! -e "$destf.sha512" ]; then
    printf "%s is missing though\n" "$destf.sha512"
    exit 1
  fi
  if [ ! -e "$destf.deps" ]; then
    printf "Missing file %s while %s is present\n" "$destf.deps" "$destf.sha512"
    exit 1
  fi
  printf "Going to verify hash.\n"
  sha512sum -c "$destf.sha512"
  exit $?
fi

foundappsrepotag=
if [ -e "$destd/$destf.deps" ]; then
  printf "Found file %s\n" "$destf.deps"
  if [ ! -e "$destd/$destf.sha512" ]; then
    printf "Missing file %s while %s is present\n" "$destf.sha512" "$destf.deps"
    exit 1
  fi
  foundappsrepotag="$(sed -n "s:^appsrepotag=\(.\{1,\}\)$:\1:p" "$destd/$destf.deps")"
  if [ -z "$foundappsrepotag" ]; then
    printf "No appsrepotag defined in %s\n" "$destf.deps"
    exit 1
  fi
  appsrepotag="$foundappsrepotag"
fi

printf "Building verisigner from tag %s using apps-repo tag %s" "$tag" "$appsrepotag"
if [ -n "$foundappsrepotag" ]; then
  printf " (found in .deps-file)"
fi
printf "\n"

cname="tkey-build"

podman run -it --name "$cname" \
       --mount type=bind,source="$(pwd)",target=/contrib \
       ghcr.io/tillitis/tkey-builder:1 \
       /bin/bash /contrib/containerbuild "$tag" "$appsrepotag"

podman cp "$cname":/tkey-verification/apps/verisigner/app.bin "$destd/$destf"

podman >/dev/null rm "$cname"

printf "Built %s\n" "$destf"

cd "$destd"

if [ -z "$foundappsrepotag" ]; then
  tagstr="$(printf 'appsrepotag=%s' "$appsrepotag")"
  printf "Writing \`%s\` to new file %s\n" "$tagstr" "$destf.deps"
  printf >"$destf.deps" "%s\n" "$tagstr"
fi

if [ ! -e "$destf.sha512" ]; then
  printf "Hash file doesn't exist. Creating %s\n" "$destf.sha512"
  sha512sum >"$destf.sha512" "$destf"
  exit 0
fi
printf "Going to verify hash.\n"
sha512sum -c "$destf.sha512"
exit $?
