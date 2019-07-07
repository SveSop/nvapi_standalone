# NVAPI (wine-staging)

An attempt to build WINE's NvAPI implementation outside a WINE source tree.
Original source: https://github.com/pchome/wine-playground/tree/master/nvapi  

Some custom mods for driver version++  

## Requirements:  
- [WINE](https://www.winehq.org/)  
- [Meson](http://mesonbuild.com/)  

## How to build  

./package-release.sh destdir  

## How to install  

Setup script will be located in:  
destdir/bin/setup_nvapi_32.sh (for 32-bit install)  
destdir/bin/setup_nvapi_64.sh (for 64-bit install)  

eg. 32-bit  
WINEPREFIX=/your/wine/prefix ./setup_nvapi_32.sh install  

OBS! For a x86_64 WINEPREFIX you need to run BOTH scripts!  

This creates symlinks in the wineprefix + creates dll-override that ENABLE nvapi. This MAY cause problems when using DXVK!  

## Goal  

This is a "lite" version of nvapi that will try to implement functions for nVidia adapters and gaming with DXVK. If you  
want to do testing of various nvapi functions, it is probably best to use the master branch.  

## Working on  

* Implement SetDepthBoundsTest  
