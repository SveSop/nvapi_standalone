#!/bin/sh

# prepare tree
git init

mkdir -p include
mkdir -p dlls



# path to WINE sources
git remote add wine_staging git://github.com/wine-compholio/wine-patched.git

# fetch WINE git info
git fetch --depth=1 wine_staging master



# get wine include files
cd include
git checkout wine_staging/master -- ../include
cd ..


# get nvapi dlls
cd dlls
git checkout wine_staging/master -- ../dlls/nvapi
git checkout wine_staging/master -- ../dlls/nvapi64
git checkout wine_staging/master -- ../dlls/nvcuda
git checkout wine_staging/master -- ../dlls/nvcuvid
git checkout wine_staging/master -- ../dlls/nvencodeapi
git checkout wine_staging/master -- ../dlls/nvencodeapi64
cd ..


# Add option to build d3d9 only
patch -p1 < build_d3d11_option.patch
