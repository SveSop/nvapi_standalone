#!/bin/bash

set -e

if [ -z "$1" ]; then
  echo "Usage: package-release.sh destdir"
  exit 1
fi

NVAPI_SRC_DIR=`dirname $(readlink -f $0)`
NVAPI_BUILD_DIR=$(realpath "$1")"/nvapi"

if [ -e "$NVAPI_BUILD_DIR" ]; then
  echo "Build directory $NVAPI_BUILD_DIR already exists"
  exit 1
fi

function build_arch {
  export WINEARCH="win$1"
  export WINEPREFIX="$NVAPI_BUILD_DIR/wine.$1"
  
  cd "$NVAPI_SRC_DIR"

  meson --cross-file "$NVAPI_SRC_DIR/build-wine$1.txt"  \
        --buildtype "release"                         \
        --prefix "$NVAPI_BUILD_DIR/install.$1"         \
        --libdir="lib$1"				\
	--strip                                       \
        "$NVAPI_BUILD_DIR/build.$1"

  cd "$NVAPI_BUILD_DIR/build.$1"
  ninja install

  mv "$NVAPI_BUILD_DIR/install.$1/lib$1" "$NVAPI_BUILD_DIR"
  mv "$NVAPI_BUILD_DIR/install.$1/fakedlls" "$NVAPI_BUILD_DIR/fakedlls$1"
  if [ ! -e "$NVAPI_BUILD_DIR/bin" ]; then
	mkdir "$NVAPI_BUILD_DIR/bin"
  fi
  cp "$NVAPI_BUILD_DIR/install.$1/bin/setup_nvapi.sh" "$NVAPI_BUILD_DIR/bin/setup_nvapi_$1.sh"
  rm -R "$NVAPI_BUILD_DIR/build.$1"
  rm -R "$NVAPI_BUILD_DIR/install.$1"
}

build_arch 64
build_arch 32
