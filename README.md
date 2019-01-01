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
