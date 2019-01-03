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

For a x86_64 WINEPREFIX you need to run BOTH scripts!  


This creates symlinks in the wineprefix + creates dll-override that ENABLE nvapi. This is known to cause problems when using DXVK!  

## Goal  

The aim is to provide some more functions to NvAPI so that it will fake my GTX970 as best it can.

## Changes

* Updated faked driverversion to 417 revision + change to GTX 970  
* Added the NvAPI_GPU_GetSystemType to set "Desktop"  
* Added NvAPI_GPU_GetVbiosVersionString to output version: BIOS: 84.04.1F.00.01  
* Updated and added a couple of (so far empty) functions.  

## Working on  

* Trying to fake GPU MHz and VRAM MHz clocks  

