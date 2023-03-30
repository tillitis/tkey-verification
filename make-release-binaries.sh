#!/bin/sh -e

if ! git diff-index --quiet --cached HEAD --; then
  printf "repo has staged changes\n"
  exit 1
fi

version="$(git describe --dirty --always | sed -n "s/^v\([0-9]\+\.[0-9]\+\.[0-9]\+\)/\1/p")"
if [ -z "$version" ]; then
  printf "found no tag (with v-prefix) to use for version\n"
  exit 1
fi

rest="$(printf "%s" "$version" | sed -n "s/^[0-9]\+\.[0-9]\+\.[0-9]\+\(.*\)$/\1/p")"

if [ -n "$rest" ]; then
  printf "%s: repo has commit after last tag, or git tree is dirty\n" "$version"
  exit 1
fi

if [ -e release ]; then
  printf "release dir already exists\n"
  exit 1
fi

make -s clean

make appbins-from-tags

printf "Building release binaries for version %s\n" "$version"

cp vendor-signing-pubkeys.txt ./internal/vendorsigning/vendor-signing-pubkeys.txt

mkdir release

cmd="tkey-verification"
export GOARCH=amd64

export CGO_ENABLED=0
GOOS=linux   go build -v -ldflags "-X main.version=$version" -o "release/${cmd}_${version}_linux-$GOARCH"   ./cmd/$cmd
GOOS=windows go build -v -ldflags "-X main.version=$version" -o "release/${cmd}_${version}_windows-$GOARCH" ./cmd/$cmd

export CGO_ENABLED=1
# TODO can't build for macos, go-serial/enumerator requires libs/C stuff on the
# host compile (and also CGO ofcourse)
#GOOS=darwin  go build -v -ldflags "-X main.version=$version" -o "release/${cmd}_${version}_macos-$GOARCH"   ./cmd/$cmd

cd release
for f in "$cmd"_*; do
  sha512sum "$f" >"$f.sha512"
done
cd ..

make -s clean

ls -l release/*
