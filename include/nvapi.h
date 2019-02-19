/*
 * Copyright (C) 2015 Michael Müller
 * Copyright (C) 2019 Sveinar Søpler
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef __WINE_NVAPI_H
#define __WINE_NVAPI_H

#include "pshpack8.h"

typedef unsigned char NvU8;
typedef unsigned int NvU32;
typedef signed int NvS32;

#define NvAPI_Status int

#define NVAPI_OK 0
#define NVAPI_ERROR -1
#define NVAPI_LIBRARY_NOT_FOUND -2
#define NVAPI_NO_IMPLEMENTATION -3
#define NVAPI_INVALID_ARGUMENT -5
#define NVAPI_NVIDIA_DEVICE_NOT_FOUND -6
#define NVAPI_END_ENUMERATION -7
#define NVAPI_INVALID_HANDLE -8
#define NVAPI_INCOMPATIBLE_STRUCT_VERSION -9
#define NVAPI_INVALID_POINTER -14
#define NVAPI_EXPECTED_LOGICAL_GPU_HANDLE -100
#define NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE -101
#define NVAPI_NOT_SUPPORTED -104
#define NVAPI_NO_ACTIVE_SLI_TOPOLOGY -113
#define NVAPI_STEREO_NOT_INITIALIZED -140
#define NVAPI_UNREGISTERED_RESOURCE -170
#define NVAPI_FIRMWARE_OUT_OF_DATE -199
#define NVAPI_MAX_COOLERS_PER_GPU_VER1  3
#define NVAPI_MAX_COOLERS_PER_GPU_VER2  20
#define NVAPI_MAX_COOLERS_PER_GPU_VER3 NVAPI_MAX_COOLERS_PER_GPU_VER2
#define NVAPI_MAX_COOLERS_PER_GPU NVAPI_MAX_COOLERS_PER_GPU_VER3
#define NVAPI_MIN_COOLER_LEVEL 0
#define NVAPI_MAX_COOLER_LEVEL 100
#define NVAPI_MAX_COOLER_LEVELS 24
#define NVAPI_MAX_GPU_PERF_CLOCKS 32
#define NVAPI_MAX_GPU_PERF_VOLTAGES 16
#define NVAPI_MAX_GPU_PERF_PSTATES 16

#define NVAPI_SHORT_STRING_MAX 64
#define NVAPI_LONG_STRING_MAX 256
#define NVAPI_PHYSICAL_GPUS 32
#define NVAPI_MAX_PHYSICAL_GPUS 64
#define NVAPI_MAX_LOGICAL_GPUS 64
#define NVAPI_MAX_GPU_CLOCKS 32
#define NVAPI_MAX_GPU_PUBLIC_CLOCKS 32
#define NVAPI_MAX_THERMAL_SENSORS_PER_GPU 3
#define NVAPI_MAX_GPU_PSTATE20_CLOCKS 8
#define NVAPI_MAX_GPU_PSTATE20_PSTATES 16
#define NVAPI_MAX_GPU_PSTATE20_BASE_VOLTAGES 4
#define NVAPI_MAX_GPU_UTILIZATIONS 8
#define NVAPI_ADVANCED_DISPLAY_HEADS 4
#define NVAPI_MAX_DISPLAYS (NVAPI_PHYSICAL_GPUS * NVAPI_ADVANCED_DISPLAY_HEADS)
#define NVAPI_MAX_PROCESSES 128

typedef char NvAPI_ShortString[NVAPI_SHORT_STRING_MAX];
typedef char NvAPI_LongString[NVAPI_LONG_STRING_MAX];

#define MAKE_NVAPI_VERSION(type,version) (NvU32)(sizeof(type) | ((version)<<16))

typedef void *NvPhysicalGpuHandle;
typedef void *NvLogicalGpuHandle;
typedef void *NvDisplayHandle;
typedef void *StereoHandle;
typedef void *NVDX_ObjectHandle;

typedef enum
{
    NVAPI_DEVICE_FEATURE_LEVEL_NULL      = -1,
    NVAPI_DEVICE_FEATURE_LEVEL_10_0      = 0,
    NVAPI_DEVICE_FEATURE_LEVEL_10_0_PLUS = 1,
    NVAPI_DEVICE_FEATURE_LEVEL_10_1      = 2,
    NVAPI_DEVICE_FEATURE_LEVEL_11_0      = 3,
} NVAPI_DEVICE_FEATURE_LEVEL;

typedef struct
{
    NvU32              version;
    NvU32              drvVersion;
    NvU32              bldChangeListNum;
    NvAPI_ShortString  szBuildBranchString;
    NvAPI_ShortString  szAdapterString;
} NV_DISPLAY_DRIVER_VERSION;

#define NV_DISPLAY_DRIVER_VERSION_VER MAKE_NVAPI_VERSION(NV_DISPLAY_DRIVER_VERSION, 1)

typedef enum
{
    NV_GPU_CLOCK_FREQUENCIES_CURRENT_FREQ = 0,
    NV_GPU_CLOCK_FREQUENCIES_BASE_CLOCK = 1,
    NV_GPU_CLOCK_FREQUENCIES_BOOST_CLOCK = 2,
    NV_GPU_CLOCK_FREQUENCIES_CLOCK_TYPE_NUM = 3
} NV_GPU_CLOCK_FREQUENCIES_CLOCK_TYPE;

typedef enum
{
    NV_SYSTEM_TYPE_GPU_UNKNOWN     = 0,
    NV_SYSTEM_TYPE_IGPU            = 1, /* Integrated GPU */
    NV_SYSTEM_TYPE_DGPU            = 2, /* Discrete GPU */
} NV_GPU_TYPE;

typedef enum
{
    NVAPI_GPU_BUS_TYPE_UNDEFINED    = 0,
    NVAPI_GPU_BUS_TYPE_PCI          = 1,
    NVAPI_GPU_BUS_TYPE_AGP          = 2,
    NVAPI_GPU_BUS_TYPE_PCI_EXPRESS  = 3,
    NVAPI_GPU_BUS_TYPE_FPCI         = 4,
    NVAPI_GPU_BUS_TYPE_AXI          = 5,
} NV_GPU_BUS_TYPE;

typedef struct
{
    NvU32		version;
    NvU32		reserved;
    struct {
        NvU32   bIsPresent:1;
        NvU32   reserved:31;
        NvU32   frequency;
    }domain[NVAPI_MAX_GPU_PUBLIC_CLOCKS];
} NV_GPU_CLOCK_FREQUENCIES_V1;

#define NV_GPU_CLOCK_FREQUENCIES_V1_VER MAKE_NVAPI_VERSION(NV_GPU_CLOCK_FREQUENCIES_V1, 1)
typedef NV_GPU_CLOCK_FREQUENCIES_V1 NV_GPU_CLOCK_FREQUENCIES;

typedef struct {
    int value;
    struct {
        int mindelta;
        int maxdelta;
    } valueRange;
} NV_GPU_PERF_PSTATES20_PARAM_DELTA;

typedef struct {
    NvU32 domainId;
    NvU32 typeId;
    NvU32 bIsEditable:1;
    NvU32 reserved:31;
    NV_GPU_PERF_PSTATES20_PARAM_DELTA freqDelta_kHz;
    union {
        struct {
            NvU32 freq_kHz;
        } single;
        struct {
            NvU32 minFreq_kHz;
            NvU32 maxFreq_kHz;
            NvU32 domainId;
            NvU32 minVoltage_uV;
            NvU32 maxVoltage_uV;
        } range;
    } data;
} NV_GPU_PSTATE20_CLOCK_ENTRY_V1;

typedef struct {
    NvU32   domainId;
    NvU32   bIsEditable:1;
    NvU32   reserved:31;
    NvU32   volt_uV;
    int     voltDelta_uV;
} NV_GPU_PSTATE20_BASE_VOLTAGE_ENTRY_V1;

typedef struct
{
    NvU32 version;
    NvU32 flags;
    struct {
	NvU32 bIsPresent;
        NvU32 percentage[5];
        NvU32 unknown:2;
    } usages[8];
} NV_USAGES_INFO_V1;

#define NV_USAGES_INFO_V1_VER MAKE_NVAPI_VERSION(NV_USAGES_INFO_V1, 1)
typedef NV_USAGES_INFO_V1 NV_USAGES_INFO;

typedef struct
{
    NvU32   version;
    NvU32   count;
    struct {
       NvU32 type;					/* 0 = "none", 1 = "Fan", 2 = "Water", 3 = "Liquid_NO2" */
       NvU32 controller;				/* 0 = "none", 1 = "ADI", 2 = "Internal" */
       NvU32 defaultMinLevel;
       NvU32 defaultMaxLevel;
       NvU32 currentMinLevel;
       NvU32 currentMaxLevel;
       NvU32 currentLevel;				/* Current % value */
       NvU32 defaultPolicy;				/* 0 = "None", 1 = "Manual", 2 = "Perf", 4 = "Discrete", 8 = "Continous HW", 16 = "Continous SW", 32 = "Default" */
       NvU32 currentPolicy;				/* Same as above */
       NvU32 target;					/* 0 = "none", 1 = "GPU", 2 = "Memory", 4 = "Power", 7 = "All" */
       NvU32 controlType;				/* toggle or variable ? */
       NvU32 active;					/* 0 = "inactive", 1 = "Active" */
    } cooler[NVAPI_MAX_COOLERS_PER_GPU_VER3];
} NV_GPU_COOLER_SETTINGS;

#define NV_GPU_COOLER_SETTINGS_VER MAKE_NVAPI_VERSION(NV_GPU_COOLER_SETTINGS, 1)

typedef struct
{
    NvU32 version;
    NvU32 processPID;
    NvAPI_LongString processName;
} NV_ACTIVE_APP;

#define NV_ACTIVE_APPS_INFO_VER MAKE_NVAPI_VERSION(NV_ACTIVE_APP, 2)

typedef enum
{
    NVAPI_GPU_PERF_PSTATE_P0 = 0,
    NVAPI_GPU_PERF_PSTATE_P1 = 1,
} NV_GPU_PERF_PSTATE_ID;

typedef struct
{
    NvU32 version;
    NvU32 bIsEditable:1;
    NvU32 reserved:31;
    NvU32 numPstates;
    NvU32 numClocks;
    NvU32 numBaseVoltages;
       struct {
       NV_GPU_PERF_PSTATE_ID pstateId;
       NvU32 bIsEditable:1;
       NvU32 reserved:31;
       NV_GPU_PSTATE20_CLOCK_ENTRY_V1 clocks[NVAPI_MAX_GPU_PSTATE20_CLOCKS];
       NV_GPU_PSTATE20_BASE_VOLTAGE_ENTRY_V1 baseVoltages[NVAPI_MAX_GPU_PSTATE20_BASE_VOLTAGES];
    } pstates[NVAPI_MAX_GPU_PSTATE20_BASE_VOLTAGES];
       struct {
       NvU32 numVoltages;
       NV_GPU_PSTATE20_BASE_VOLTAGE_ENTRY_V1 voltages[NVAPI_MAX_GPU_PSTATE20_BASE_VOLTAGES];
    } ov;
} NV_GPU_PERF_PSTATES20_INFO_V2;

#define NV_GPU_PERF_PSTATES20_INFO_VER2 MAKE_NVAPI_VERSION(NV_GPU_PERF_PSTATES20_INFO_V2, 2)
typedef NV_GPU_PERF_PSTATES20_INFO_V2 NV_GPU_PERF_PSTATES20_INFO;

typedef enum
{
    NVAPI_GPU_PUBLIC_CLOCK_GRAPHICS = 0,
    NVAPI_GPU_PUBLIC_CLOCK_MEMORY = 4,
    NVAPI_GPU_PUBLIC_CLOCK_PROCESSOR = 7,
    NVAPI_GPU_PUBLIC_CLOCK_UNDEFINED = NVAPI_MAX_GPU_PUBLIC_CLOCKS
} NV_GPU_PUBLIC_CLOCK_ID;

typedef struct
{
    NvU32 version;
    NvU32 flags;
    NvU32 numPstates;
    NvU32 numClocks;
    NvU32 numVoltages;
    struct {
       NV_GPU_PERF_PSTATE_ID pstateId;
       NvU32 flags;
       struct {
          NV_GPU_PUBLIC_CLOCK_ID domainId;
          NvU32 flags;
          NvU32 freq;
       } clocks[NVAPI_MAX_GPU_PERF_CLOCKS];
       struct {
          NvU32 domainId;
          NvU32 flags;
          NvU32 mvolt;
       } voltages[NVAPI_MAX_GPU_PERF_VOLTAGES];
    } pstates[NVAPI_MAX_GPU_PERF_PSTATES];
} NV_GPU_PERF_PSTATES_INFO_V2;

#define NV_GPU_PERF_PSTATES_INFO_V2_VER MAKE_NVAPI_VERSION(NV_GPU_PERF_PSTATES_INFO_V2, 2)
typedef NV_GPU_PERF_PSTATES_INFO_V2 NV_GPU_PERF_PSTATES_INFO;

typedef enum
{
    NVAPI_THERMAL_TARGET_NONE          = 0,
    NVAPI_THERMAL_TARGET_GPU           = 1,     /* GPU core temperature requires NvPhysicalGpuHandle */
    NVAPI_THERMAL_TARGET_MEMORY        = 2,     /* GPU memory temperature requires NvPhysicalGpuHandle */
    NVAPI_THERMAL_TARGET_POWER_SUPPLY  = 4,     /* GPU power supply temperature requires NvPhysicalGpuHandle */
    NVAPI_THERMAL_TARGET_BOARD         = 8,     /* GPU board ambient temperature requires NvPhysicalGpuHandle */
    NVAPI_THERMAL_TARGET_UNKNOWN       = -1,
} NV_THERMAL_TARGET;

typedef struct
{
    NvU32 version;
    NvU32 count;
    struct {
       NvU32 controller;
       NvS32 defaultMinTemp;
       NvS32 defaultMaxTemp;
       NvS32 currentTemp;
       NV_THERMAL_TARGET target;
    } sensor[NVAPI_MAX_THERMAL_SENSORS_PER_GPU];
} NV_GPU_THERMAL_SETTINGS_V2;

#define NV_GPU_THERMAL_SETTINGS_VER_2 MAKE_NVAPI_VERSION(NV_GPU_THERMAL_SETTINGS_V2, 2)
typedef NV_GPU_THERMAL_SETTINGS_V2 NV_GPU_THERMAL_SETTINGS;

typedef struct
{
    NvU32 version;
    NvU32 flags;
       struct {
       NvU32 bIsPresent:1;
       NvU32 percentage;
    } utilization[NVAPI_MAX_GPU_UTILIZATIONS];
} NV_GPU_DYNAMIC_PSTATES_INFO_EX;

#define NV_GPU_DYNAMIC_PSTATES_INFO_EX_VER MAKE_NVAPI_VERSION(NV_GPU_DYNAMIC_PSTATES_INFO_EX, 2)

typedef struct
{
    NvU32 version;
    NvU32 flags;
    NvU32 count;
    NvU32 unknown;
    NvU32 value_uV;
    NvU32 buf1:30;
} NV_VOLT_STATUS_V1;

#define NV_VOLT_STATUS_V1_VER MAKE_NVAPI_VERSION(NV_VOLT_STATUS_V1, 1)
typedef NV_VOLT_STATUS_V1 NV_VOLT_STATUS;

typedef struct
{
    NvU32 version;
    NvU32 dedicatedVideoMemory;
    NvU32 availableDedicatedVideoMemory;
    NvU32 systemVideoMemory;
    NvU32 sharedSystemMemory;
    NvU32 curAvailableDedicatedVideoMemory;
    NvU32 dedicatedVideoMemoryEvictionsSize;
    NvU32 dedicatedVideoMemoryEvictionCount;
} NV_DISPLAY_DRIVER_MEMORY_INFO_V3;

#define NV_DISPLAY_DRIVER_MEMORY_INFO_V3_VER MAKE_NVAPI_VERSION(NV_DISPLAY_DRIVER_MEMORY_INFO_V3, 3)
typedef NV_DISPLAY_DRIVER_MEMORY_INFO_V3 NV_DISPLAY_DRIVER_MEMORY_INFO;

typedef struct
{
    NvU32 version;
    NvU32 maxNumAFRGroups;
    NvU32 numAFRGroups;
    NvU32 currentAFRIndex;
    NvU32 nextFrameAFRIndex;
    NvU32 previousFrameAFRIndex;
    NvU32 bIsCurAFRGroupNew;
} NV_GET_CURRENT_SLI_STATE_V1;

typedef struct
{
    NvU32 version;
    NvU32 maxNumAFRGroups;
    NvU32 numAFRGroups;
    NvU32 currentAFRIndex;
    NvU32 nextFrameAFRIndex;
    NvU32 previousFrameAFRIndex;
    NvU32 bIsCurAFRGroupNew;
    NvU32 numVRSLIGpus;
} NV_GET_CURRENT_SLI_STATE_V2;

#define NV_GET_CURRENT_SLI_STATE_VER1 MAKE_NVAPI_VERSION(NV_GET_CURRENT_SLI_STATE_V1, 1)
#define NV_GET_CURRENT_SLI_STATE_VER2 MAKE_NVAPI_VERSION(NV_GET_CURRENT_SLI_STATE_V2, 1)

#define NV_GET_CURRENT_SLI_STATE_VER NV_GET_CURRENT_SLI_STATE_VER2
#define NV_GET_CURRENT_SLI_STATE     NV_GET_CURRENT_SLI_STATE_V2

/* undocumented stuff */
typedef struct
{
    NvU32 version;
    NvU32 gpu_count;
    struct
    {
        NvPhysicalGpuHandle gpuHandle;
        NvU32 GetGPUIDfromPhysicalGPU;
    } gpus[8];
}NV_UNKNOWN_1;

#define NV_UNKNOWN_1_VER MAKE_NVAPI_VERSION(NV_UNKNOWN_1, 1)

#include "poppack.h"

#endif /* __WINE_NVAPI_H */
