# NVAPI (wine-staging)

An attempt to build WINE's NvAPI implementation outside a WINE source tree.
Original source: https://github.com/pchome/wine-playground/tree/master/nvapi  

Requires nVidia proprietary driver version 440.x or newer  

Some custom mods for driver version++  

## Requirements:  
- [WINE](https://www.winehq.org/)  
- [Meson](http://mesonbuild.com/)  

## How to build  

./package-release.sh destdir  

## How to install  

Setup script will be located in:  
destdir/setup_nvapi.sh  

eg.  
WINEPREFIX=/your/wine/prefix ./setup_nvapi.sh install  

OBS! Recommend a x86_64 WINEPREFIX as installscript may have unpredictible result in a 32-bit only wineprefix!  

This creates symlinks in the wineprefix + creates dll-override that ENABLE nvapi.  

## Goal  

This is a "lite" version of nvapi that will try to implement functions for nVidia adapters and gaming with DXVK. If you  
want to do testing of various nvapi functions, it is probably best to use the master branch.  

## Working on  

* Only game related functions  
