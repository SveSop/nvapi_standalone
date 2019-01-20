# NVAPI (wine-staging)

An attempt to build WINE's NvAPI implementation outside a WINE source tree.
Original source: https://github.com/pchome/wine-playground/tree/master/nvapi  

Some custom mods for driver version++  

## Requirements:  
- [WINE](https://www.winehq.org/)  
- [Meson](http://mesonbuild.com/)  
- libxnvctrl-dev (both amd64 and i386)  

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

The aim is to provide some more functions to NvAPI so that it will fake my GTX970 as best it can.

## Changes

* Updated faked driverversion to 415 revision + change to GTX 970  
* Added the NvAPI_GPU_GetSystemType to set "Desktop"  
* Added NvAPI_GPU_GetVbiosVersionString to output version: BIOS: 84.04.36.00.f1  
* Updated and added a couple of (so far empty) functions.  
* Fake GPU MHz and VRAM MHz clocks
* Fake GPU Volt
* Changed to use driver 415.22 inline with actual Linux version.
* Fake fan rpm
* More fake memory settings
* Loads of useless crap  
* Implementing using NVCtrl interface to get real values  

## Working on  

* Changing "fake" values over to using NVCtrl library.  
* For some reason adding NvAPI_GPU_GetBusId the tool "GPU Caps Viewer" now display CUDA correctly, but no OpenCL.

## Info  

Loads of reference info here:  

[https://docs.nvidia.com/gameworks/content/gameworkslibrary/coresdk/nvapi/annotated.html](https://docs.nvidia.com/gameworks/content/gameworkslibrary/coresdk/nvapi/annotated.html)  
[https://1vwjbxf1wko0yhnr.wordpress.com/2015/08/10/overclocking-tools-for-nvidia-gpus-suck-i-made-my-own/](https://1vwjbxf1wko0yhnr.wordpress.com/2015/08/10/overclocking-tools-for-nvidia-gpus-suck-i-made-my-own/)  
[https://github.com/verybigbadboy/NVAPI-example](https://github.com/verybigbadboy/NVAPI-example)  

Tool to check various GPU options:  
[http://www.ozone3d.net/gpu_caps_viewer/](http://www.ozone3d.net/gpu_caps_viewer/)  
