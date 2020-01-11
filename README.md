# NVAPI (wine-staging)

An attempt to build WINE's NvAPI implementation outside a WINE source tree.
Original source: https://github.com/pchome/wine-playground/tree/master/nvapi  

Require nVidia proprietary driver version 440.x or newer  

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

The aim is to provide some more functions to NvAPI so that it will fake nVidia cards as best it can.  
The "fakedll" folders have the fake dll's used by wine incase one wants to use the winelib created  
dll.so files directly with a custom wine. You need to copy the dll.so files in their respective  
lib/lib64 folders in your custom wine binary folder. Same with the fakedll's. (Recommended only with  
wine-staging binaries!).  

## Changes

* Implementing using nvml and nvidia-settings interface to get real values  
* A few functions:  
  * GPU Load %  
  * GPU Memory amount  
  * GPU Name  
  * GPU BusID  
  * Bios version  
  * Driver and branch version  
  * GPU Vendor:Device ID's  
  * GPU Temp  
  * GPU / Memory clocks  
  * Video Memory usage  
  * Video Memory controller utilization  
  * Get shader/cuda cores from NVCtrl  
  * Read GPU Voltage  
  * Calculate GPU fan speed
  * Get IRQ  
  * Implement video memory bandwidth  

## Working on  

* Implement correct performancelevels.  

## Info  

Loads of reference info here:  

[https://docs.nvidia.com/gameworks/content/gameworkslibrary/coresdk/nvapi/annotated.html](https://docs.nvidia.com/gameworks/content/gameworkslibrary/coresdk/nvapi/annotated.html)  
[https://1vwjbxf1wko0yhnr.wordpress.com/2015/08/10/overclocking-tools-for-nvidia-gpus-suck-i-made-my-own/](https://1vwjbxf1wko0yhnr.wordpress.com/2015/08/10/overclocking-tools-for-nvidia-gpus-suck-i-made-my-own/)  
[https://github.com/verybigbadboy/NVAPI-example](https://github.com/verybigbadboy/NVAPI-example)  

Tool to check various GPU options:  
[http://www.ozone3d.net/gpu_caps_viewer/](http://www.ozone3d.net/gpu_caps_viewer/)  
