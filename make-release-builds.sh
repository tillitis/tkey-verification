#!/bin/sh -e

cat <<EOF
Note that it is your responsibility that the code that is built as a specific
version comes from a clean version tag -- or more importantly, from a later
commit that does not alter the tkey-verification source/dependencies in any
way. Of course, this applies also to any changes in the worktree.

EOF

version="$1"
if [ -z "$version" ]; then
  printf "give me a version number\n"
  exit 1
fi
shift

if ! hash 2>/dev/null sha512sum; then
  sha512sum() {
    shasum -a 512 "$@"
  }
fi

# Check if we have the appbins we need before building them all. This allows
# user to download/copy them in place instead of having them built here.
cd internal/appbins/bins
missing=
for hashf in *.sha512; do
  if ! sha512sum -c "$hashf"; then
    missing=missing
  fi
done
cd ../../..
if [ -n "$missing" ]; then
  make appbins-from-tags
fi

cp -af vendor-signing-pubkeys.txt ./internal/vendorsigning/vendor-signing-pubkeys.txt

targets="linux windows darwin"
printf "Will build for: %s\n" "$targets"

outd="release-builds"
mkdir -p "$outd"

cmd="tkey-verification"

if [ -e buildall ]; then
  printf "./buildall already exists, from a failed run?\n"
  exit 1
fi

cat >buildall <<EOF
#!/bin/sh -e
export CGO_ENABLED=0
EOF
chmod +x buildall

for os in $targets; do
  outos="$os"
  archs="amd64"
  if [ "$os" = "darwin" ]; then
    outos="macos"
    archs="amd64 arm64"
  fi
  suffix=""
  [ "$os" = "windows" ] && suffix=".exe"

  for arch in $archs; do
    cat >>buildall <<EOF
printf "Building $version for $os $arch\n"
export GOOS=$os GOARCH=$arch
go build -trimpath -buildvcs=false -ldflags="-X=main.version=$version" \
   -o "$outd/${cmd}_${version}_$outos-$arch$suffix" ./cmd/$cmd
EOF
  done
done

podman run --rm -it --mount "type=bind,source=$(pwd),target=/build" -w /build \
       ghcr.io/tillitis/tkey-builder:2 ./buildall
rm -f buildall

printf "Creating MacOS universal binary\n"
make -s -C gotools lipo
cd "$outd"
../gotools/lipo -output "${cmd}_${version}_macos-universal" -create \
                "${cmd}_${version}_macos-amd64" \
                "${cmd}_${version}_macos-arm64"

printf "Verifying hashes:\n"
for binf in "$cmd"*; do
  [ "${binf##*.}" = "sha512" ] && continue
  if [ ! -e "$binf.sha512" ]; then
    printf "Hash file doesn't exist. Creating %s\n" "$binf.sha512"
    sha512sum >"$binf.sha512" "$binf"
  else
    sha512sum -c "$binf.sha512"
  fi
done
cd ..

set -x
ls -l "$outd"
