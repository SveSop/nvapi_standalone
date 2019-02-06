/*
 * Copyright (C) 2015 Michael Müller
 * Copyright (C) 2015 Sebastian Lackner
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

#include "config.h"
#include "wine/port.h"

#include <stdarg.h>
#include "Xlib.h"
#include <NVCtrl/NVCtrlLib.h>

#define COBJMACROS
#include "initguid.h"
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "wine/debug.h"
#include "wine/list.h"
#include "nvapi.h"
#include "d3d9.h"
#include "d3d11.h"
#include "wine/wined3d.h"

WINE_DEFAULT_DEBUG_CHANNEL(nvapi);

#define FAKE_PHYSICAL_GPU ((NvPhysicalGpuHandle)0xdead0001)
#define FAKE_DISPLAY ((NvDisplayHandle)0xdead0002)
#define FAKE_LOGICAL_GPU ((NvLogicalGpuHandle)0xdead0003)
#define FAKE_DISPLAY_ID ((NvU32)0xdead0004)

#if defined(__i386__) || defined(__x86_64__)

Display *display;
int clocks, gputemp, gpumaxtemp, gpuvram;
char *gfxload, *nvver;

static NvAPI_Status CDECL unimplemented_stub(unsigned int offset)
{
    FIXME("function 0x%x is unimplemented!\n", offset);
    return NVAPI_NO_IMPLEMENTATION;
}

#ifdef __i386__

#include "pshpack1.h"
struct thunk
{
    unsigned char  push_ebp;
    unsigned short mov_esp_ebp;
    unsigned char  sub_0x08_esp[3];
    unsigned char  mov_dword_esp[3];
    unsigned int   offset;
    unsigned char  mov_eax;
    void           *stub;
    unsigned short call_eax;
    unsigned char  leave;
    unsigned char  ret;
};
#include "poppack.h"

static void* prepare_thunk(struct thunk *thunk, unsigned int offset)
{
    thunk->push_ebp         = 0x55;
    thunk->mov_esp_ebp      = 0xE589;
    thunk->sub_0x08_esp[0]  = 0x83;
    thunk->sub_0x08_esp[1]  = 0xEC;
    thunk->sub_0x08_esp[2]  = 0x08;
    thunk->mov_dword_esp[0] = 0xC7;
    thunk->mov_dword_esp[1] = 0x04;
    thunk->mov_dword_esp[2] = 0x24;
    thunk->offset           = offset;
    thunk->mov_eax          = 0xB8;
    thunk->stub             = &unimplemented_stub;
    thunk->call_eax         = 0xD0FF;
    thunk->leave            = 0xC9;
    thunk->ret              = 0xC3;
    return thunk;
}

#else

#include "pshpack1.h"
struct thunk
{
    unsigned short mov_rcx;
    unsigned int   offset;
    unsigned int   zero;
    unsigned short mov_rax;
    void           *stub;
    unsigned short jmp_rax;
};
#include "poppack.h"

static void* prepare_thunk(struct thunk *thunk, unsigned int offset)
{
    thunk->mov_rcx           = 0xB948;
    thunk->offset            = offset;
    thunk->zero              = 0;
    thunk->mov_rax           = 0xB848;
    thunk->stub              = &unimplemented_stub;
    thunk->jmp_rax           = 0xE0FF;
    return thunk;
}

#endif

struct thunk_entry
{
    struct list entry;
    int num_thunks;
    struct thunk thunks[0];
};

static struct list unimplemented_thunks = LIST_INIT( unimplemented_thunks );
static SYSTEM_BASIC_INFORMATION system_info;

static RTL_CRITICAL_SECTION unimplemented_thunk_section;
static RTL_CRITICAL_SECTION_DEBUG critsect_debug =
{
    0, 0, &unimplemented_thunk_section,
    { &critsect_debug.ProcessLocksList, &critsect_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": unimplemented_thunk_section") }
};
static RTL_CRITICAL_SECTION unimplemented_thunk_section = { &critsect_debug, -1, 0, 0, 0, 0 };

static void* lookup_thunk_function(unsigned int offset)
{
    struct list *ptr;
    unsigned int i;

    /* check for existing thunk */
    LIST_FOR_EACH( ptr, &unimplemented_thunks )
    {
        struct thunk_entry *entry = LIST_ENTRY( ptr, struct thunk_entry, entry );
        for (i = 0; i < entry->num_thunks; i++)
            if (entry->thunks[i].offset == offset)
                return &entry->thunks[i];
    }

    return NULL;
}

static void* allocate_thunk_function(unsigned int offset)
{
    struct thunk_entry *entry;
    struct list *ptr;

    /* append after last existing thunk if possible */
    if ((ptr = list_tail( &unimplemented_thunks )))
    {
        entry = LIST_ENTRY( ptr, struct thunk_entry, entry );
        if (FIELD_OFFSET( struct thunk_entry, thunks[entry->num_thunks + 1] ) <= system_info.PageSize)
            return prepare_thunk( &entry->thunks[entry->num_thunks++], offset );
    }

    /* allocate a new block */
    entry = VirtualAlloc( NULL, system_info.PageSize, MEM_COMMIT | MEM_RESERVE,
                          PAGE_EXECUTE_READWRITE );
    if (entry)
    {
        list_add_tail( &unimplemented_thunks, &entry->entry );
        entry->num_thunks = 1;
        return prepare_thunk( &entry->thunks[0], offset );
    }

    return NULL;
}

static void* get_thunk_function(unsigned int offset)
{
    void *ret;
    TRACE("(%x)\n", offset);

    EnterCriticalSection( &unimplemented_thunk_section );
    ret = lookup_thunk_function( offset );
    if (!ret) ret = allocate_thunk_function( offset );
    LeaveCriticalSection( &unimplemented_thunk_section );
    return ret;
}

static void init_thunks(void)
{
    NtQuerySystemInformation( SystemBasicInformation, &system_info, sizeof(system_info), NULL );
    /* we assume here that system_info.PageSize will always be great enough to hold at least one thunk */
}

static void free_thunks(void)
{
    struct list *ptr, *ptr2;
    EnterCriticalSection( &unimplemented_thunk_section );
    LIST_FOR_EACH_SAFE( ptr, ptr2, &unimplemented_thunks )
    {
        struct thunk_entry *entry = LIST_ENTRY( ptr, struct thunk_entry, entry );
        list_remove( ptr );
        VirtualFree( entry, 0, MEM_RELEASE );
    }
    LeaveCriticalSection( &unimplemented_thunk_section );
}

#else

static NvAPI_Status CDECL unimplemented_stub()
{
    FIXME("function is unimplemented!\n");
    return NVAPI_NO_IMPLEMENTATION;
}

static void* get_thunk_function(unsigned int offset)
{
    TRACE("(%x)\n", offset);
    return &unimplemented_stub;
}

static void init_thunks(void)
{
    /* unimplemented */
}

static void free_thunks(void)
{
    /* unimplemented */
}

#endif


static NvAPI_Status CDECL NvAPI_Initialize(void)
{
    TRACE("()\n");
    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_GPU_CudaEnumComputeCapableGpus(NV_UNKNOWN_1 *param)
{
    TRACE("(%p)\n", param);

    if (!param)
        return NVAPI_INVALID_ARGUMENT;

    if (param->version != NV_UNKNOWN_1_VER)
        return NVAPI_INCOMPATIBLE_STRUCT_VERSION;

    param->gpu_count = 1;
    param->gpus[0].gpuHandle = FAKE_PHYSICAL_GPU;
    param->gpus[0].GetGPUIDfromPhysicalGPU = 11;

    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_GetGPUIDfromPhysicalGPU(NvPhysicalGpuHandle gpuHandle, NvPhysicalGpuHandle *retHandle)
{
    TRACE("(%p, %p)\n", gpuHandle, retHandle);

    if (!gpuHandle)
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;

    if (!retHandle)
        return NVAPI_INVALID_ARGUMENT;

    if (gpuHandle == FAKE_PHYSICAL_GPU)
        *retHandle = (void *)gpuHandle;
    else
    {
        FIXME("invalid handle: %p\n", gpuHandle);
        *retHandle = (void*)0xffffffff;
    }

    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_GetPhysicalGPUFromGPUID(NvPhysicalGpuHandle gpuHandle, NvPhysicalGpuHandle *retHandle)
{
    TRACE("(%p, %p)\n", gpuHandle, retHandle);

    if (!gpuHandle || !retHandle)
        return NVAPI_INVALID_ARGUMENT;

    if (gpuHandle == FAKE_PHYSICAL_GPU)
        *retHandle = (void *)gpuHandle;
    else
    {
        FIXME("invalid handle: %p\n", gpuHandle);
        *retHandle = (void *)0xffffffff;
    }

    return NVAPI_OK;
}

static int get_nv_driver_version(void)
{
    if (!(display = XOpenDisplay(NULL))) {
        TRACE("(%p)\n", XDisplayName(NULL));
        return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
    }
    Bool drvver=XNVCTRLQueryTargetStringAttribute(display,
                                                NV_CTRL_TARGET_TYPE_GPU,
                                                0, // target_id
                                                0, // display_mask
                                                NV_CTRL_STRING_NVIDIA_DRIVER_VERSION,
                                                &nvver);
    XCloseDisplay(display);
    if (!drvver) {
        FIXME("invalid driver: %s\n", nvver);
        return NVAPI_INVALID_POINTER;
    }
    return (drvver);
}

static NvAPI_Status CDECL NvAPI_GetDisplayDriverVersion(NvDisplayHandle hNvDisplay, NV_DISPLAY_DRIVER_VERSION *pVersion)
{
    char *adapter;
    TRACE("(%p, %p)\n", hNvDisplay, pVersion);

    if (hNvDisplay && hNvDisplay != FAKE_DISPLAY)
    {
        FIXME("invalid display handle: %p\n", hNvDisplay);
        return NVAPI_INVALID_HANDLE;
    }

    if (!pVersion)
        return NVAPI_INVALID_ARGUMENT;
    /* Return driver version */
    get_nv_driver_version();
    strcpy(pVersion->szBuildBranchString, nvver);	/* Full driver version string */
    /* Create "short" driver version */
    strcpy(&nvver[3], &nvver[3 + 1]);
    pVersion->drvVersion = strtoul(nvver, &nvver, 10);	/* Short driver version string */
    pVersion->bldChangeListNum = 0;

    /* Get Adaptername from NVCtrl */
    if (!(display = XOpenDisplay(NULL))) {
        TRACE("(%p)\n", XDisplayName(NULL));
        return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
    }
    Bool check=XNVCTRLQueryTargetStringAttribute(display,
                                                NV_CTRL_TARGET_TYPE_GPU,
                                                0, // target_id
                                                0, // display_mask
                                                NV_CTRL_STRING_PRODUCT_NAME,
                                                &adapter);
    XCloseDisplay(display);
    if (!check) {
        return NVAPI_INVALID_POINTER;
    }
    strcpy(pVersion->szAdapterString, adapter);		/* Report adapter name from NvAPI */
    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_GetAssociatedNvidiaDisplayHandle(const char *szDisplayName, NvDisplayHandle *pNvDispHandle)
{
    TRACE("(%s, %p)\n", szDisplayName, pNvDispHandle);

    *pNvDispHandle = FAKE_DISPLAY;
    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_GetPhysicalGPUsFromDisplay(NvDisplayHandle hNvDisp, NvPhysicalGpuHandle nvGPUHandle[NVAPI_MAX_PHYSICAL_GPUS], NvU32 *pGpuCount)
{
    TRACE("(%p, %p, %p)\n", hNvDisp, nvGPUHandle, pGpuCount);

    nvGPUHandle[0] = FAKE_PHYSICAL_GPU;
    *pGpuCount = 1;

    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_Stereo_Disable(void)
{
    TRACE("()\n");
    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_Stereo_IsEnabled(NvU8 *pIsStereoEnabled)
{
    TRACE("(%p)\n", pIsStereoEnabled);

    *pIsStereoEnabled = 0;
    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_Stereo_CreateHandleFromIUnknown(void *pDevice, StereoHandle *pStereoHandle)
{
    TRACE("(%p, %p)\n", pDevice, pStereoHandle);
    return NVAPI_STEREO_NOT_INITIALIZED;
}

static NvAPI_Status CDECL NvAPI_Stereo_DestroyHandle(StereoHandle stereoHandle)
{
    TRACE("(%p)\n", stereoHandle);
    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_Stereo_Activate(StereoHandle stereoHandle)
{
    TRACE("(%p)\n", stereoHandle);
    return NVAPI_STEREO_NOT_INITIALIZED;
}

static NvAPI_Status CDECL NvAPI_Stereo_Deactivate(StereoHandle stereoHandle)
{
    TRACE("(%p)\n", stereoHandle);
    return NVAPI_STEREO_NOT_INITIALIZED;
}

static NvAPI_Status CDECL NvAPI_Stereo_IsActivated(StereoHandle stereoHandle, NvU8 *pIsStereoOn)
{
    TRACE("(%p, %p)\n", stereoHandle, pIsStereoOn);

    *pIsStereoOn = 0;
    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_Stereo_GetSeparation(StereoHandle stereoHandle, float *pSeparationPercentage)
{
    TRACE("(%p, %p)\n", stereoHandle, pSeparationPercentage);
    return NVAPI_STEREO_NOT_INITIALIZED;
}

static NvAPI_Status CDECL NvAPI_Stereo_SetSeparation(StereoHandle stereoHandle, float newSeparationPercentage)
{
    TRACE("(%p, %f)\n", stereoHandle, newSeparationPercentage);
    return NVAPI_STEREO_NOT_INITIALIZED;
}

static NvAPI_Status CDECL NvAPI_Stereo_Enable(void)
{
    TRACE("()\n");
    return NVAPI_STEREO_NOT_INITIALIZED;
}

static NvAPI_Status CDECL NvAPI_D3D9_StretchRectEx(IDirect3DDevice9 *pDevice, IDirect3DResource9 *pSourceResource,
                                                   const RECT *pSourceRect, IDirect3DResource9 *pDestResource,
                                                   const RECT *pDestRect, D3DTEXTUREFILTERTYPE Filter)
{
    FIXME("(%p, %p, %p, %p, %p, %d): stub\n", pDevice, pSourceResource, pSourceRect, pDestResource, pDestRect, Filter);
    return NVAPI_UNREGISTERED_RESOURCE;
}

static NvAPI_Status CDECL NvAPI_EnumLogicalGPUs(NvLogicalGpuHandle gpuHandle[NVAPI_MAX_LOGICAL_GPUS], NvU32 *count)
{
    TRACE("(%p, %p)\n", gpuHandle, count);

    if (!gpuHandle)
        return NVAPI_INVALID_ARGUMENT;

    if (!count)
        return NVAPI_INVALID_POINTER;

    gpuHandle[0] = FAKE_LOGICAL_GPU;
    *count = 1;

    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_EnumLogicalGPUs_unknown(NvLogicalGpuHandle gpuHandle[NVAPI_MAX_LOGICAL_GPUS], NvU32 *count)
{
    TRACE("(%p, %p)\n", gpuHandle, count);
    return NvAPI_EnumLogicalGPUs(gpuHandle, count);
}

static NvAPI_Status CDECL NvAPI_GetPhysicalGPUsFromLogicalGPU(NvLogicalGpuHandle logicalGPU,
                                                              NvPhysicalGpuHandle physicalGPUs[NVAPI_MAX_PHYSICAL_GPUS],
                                                              NvU32 *count)
{
    if (!physicalGPUs)
        return NVAPI_INVALID_ARGUMENT;

    if (!count)
        return NVAPI_INVALID_POINTER;

    if (!logicalGPU)
        return NVAPI_EXPECTED_LOGICAL_GPU_HANDLE;

    if (logicalGPU != FAKE_LOGICAL_GPU)
    {
        FIXME("invalid handle: %p\n", logicalGPU);
        return NVAPI_EXPECTED_LOGICAL_GPU_HANDLE;
    }

    physicalGPUs[0] = FAKE_PHYSICAL_GPU;
    *count = 1;

    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_EnumPhysicalGPUs(NvPhysicalGpuHandle gpuHandle[NVAPI_MAX_PHYSICAL_GPUS], NvU32 *count)
{
    TRACE("(%p, %p)\n", gpuHandle, count);

    if (!gpuHandle)
        return NVAPI_INVALID_ARGUMENT;

    if (!count)
        return NVAPI_INVALID_POINTER;

    gpuHandle[0] = FAKE_PHYSICAL_GPU;
    *count = 1;

    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_GPU_GetFullName(NvPhysicalGpuHandle hPhysicalGpu, NvAPI_ShortString szName)
{
    char *adapter;

    if (!(display = XOpenDisplay(NULL))) {
        TRACE("(%p)\n", XDisplayName(NULL));
        return NVAPI_ERROR;
    }

    Bool check=XNVCTRLQueryTargetStringAttribute(display,
                                                NV_CTRL_TARGET_TYPE_GPU,
                                                0, // target_id
                                                0, // display_mask
                                                NV_CTRL_STRING_PRODUCT_NAME,
                                                &adapter);
    XCloseDisplay(display);
    if (!check) {
        return NVAPI_ERROR;
    }

    TRACE("(%p, %p)\n", hPhysicalGpu, szName);

    if (!hPhysicalGpu)
        return NVAPI_ERROR;

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_ERROR;
    }


    strcpy(szName, adapter);			/* Report adapter name from NvAPI */
    if (!szName)
        return NVAPI_ERROR;
    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_DISP_GetGDIPrimaryDisplayId(NvU32* displayId)
{
    TRACE("(%p)\n", displayId);

    if (!displayId)
        return NVAPI_INVALID_ARGUMENT;

    *displayId = FAKE_DISPLAY_ID;
    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_EnumNvidiaDisplayHandle(NvU32 thisEnum, NvDisplayHandle *pNvDispHandle)
{
    TRACE("(%u, %p)\n", thisEnum, pNvDispHandle);

    if (thisEnum >= NVAPI_MAX_DISPLAYS || !pNvDispHandle)
        return NVAPI_INVALID_ARGUMENT;

    if (thisEnum > 0)
        return NVAPI_END_ENUMERATION;

    *pNvDispHandle = FAKE_DISPLAY;
    return NVAPI_OK;
}

/* Set driver short version and branch string */
static NvAPI_Status CDECL NvAPI_SYS_GetDriverAndBranchVersion(NvU32* pDriverVersion, NvAPI_ShortString szBuildBranchString)
{
    TRACE("(%p, %p)\n", pDriverVersion, szBuildBranchString);

    if (!pDriverVersion || !szBuildBranchString)
        return NVAPI_INVALID_ARGUMENT;

    /* Return driver version */
    get_nv_driver_version();
    NvAPI_ShortString build_str = "R0_00"; 		/* Empty "branch" string */
    char *branch = nvver;
    /* Create "short" driver version */
    strcpy(&nvver[3], &nvver[3 + 1]);
    *pDriverVersion = strtoul(nvver, &nvver, 10); 	/* Short driver version string from NvAPI */
    /* Create "branch" version */
    strcpy(&branch[2], &branch[7 + 1]); 		/*  Get "major" version			*/
    lstrcpynA(szBuildBranchString, build_str, 1);	/*					*/
    szBuildBranchString[1] = '\0';			/*  Copy strings together		*/
    strcat(szBuildBranchString, branch);		/*  Creates Rxx0_00 version		*/
    memcpy(szBuildBranchString, build_str, + 1);	/*  Final branch version from NvAPI	*/
    return NVAPI_OK;
    /* Assumption: 415.22.05 is from the R410 driver "branch" (Not verified) */
}

static NvAPI_Status CDECL NvAPI_Unload(void)
{
    TRACE("()\n");
    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_D3D_GetCurrentSLIState(IUnknown *pDevice, NV_GET_CURRENT_SLI_STATE *pSliState)
{
    TRACE("(%p, %p)\n", pDevice, pSliState);

    if (!pDevice || !pSliState)
        return NVAPI_ERROR;

    if (pSliState->version != NV_GET_CURRENT_SLI_STATE_VER1 &&
        pSliState->version != NV_GET_CURRENT_SLI_STATE_VER2)
        return NVAPI_ERROR;

    /* Simulate single GPU */
    pSliState->maxNumAFRGroups = 1;
    pSliState->numAFRGroups = 1;
    pSliState->currentAFRIndex = 0;
    pSliState->nextFrameAFRIndex = 0;
    pSliState->previousFrameAFRIndex = 0;
    pSliState->bIsCurAFRGroupNew = FALSE;

    /* No VR SLI */
    if (pSliState->version == NV_GET_CURRENT_SLI_STATE_VER2)
        pSliState->numVRSLIGpus = 0;

    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_GetLogicalGPUFromDisplay(NvDisplayHandle hNvDisp, NvLogicalGpuHandle *pLogicalGPU)
{
    TRACE("(%p, %p)\n", hNvDisp, pLogicalGPU);

    if (!pLogicalGPU)
        return NVAPI_INVALID_POINTER;

    if (hNvDisp && hNvDisp != FAKE_DISPLAY)
        return NVAPI_NVIDIA_DEVICE_NOT_FOUND;

    *pLogicalGPU = FAKE_LOGICAL_GPU;
    return NVAPI_OK;
}

/* Get clocks from NVCtrl */
static int get_nv_clocks(void)
{
    if (!(display = XOpenDisplay(NULL))) {
                TRACE("(%p)\n", XDisplayName(NULL));
		return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
    }
    Bool nv_clocks=XNVCTRLQueryAttribute(display,0,0, NV_CTRL_GPU_CURRENT_CLOCK_FREQS, &clocks);
    XCloseDisplay(display);
    if (!nv_clocks) {
            FIXME("invalid display: %d\n", clocks);
            return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
        }
    return (nv_clocks);
}

/* Get GPU/MEM clocks from NVCtrl */
static NvAPI_Status CDECL NvAPI_GPU_GetAllClockFrequencies(NvPhysicalGpuHandle hPhysicalGPU, NV_GPU_CLOCK_FREQUENCIES *pClkFreqs)
{
    TRACE("(%p, %p)\n", hPhysicalGPU, pClkFreqs);

    if (hPhysicalGPU != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGPU);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    get_nv_clocks();
    int gpu=(clocks >> 16);
    short memclk=clocks;
    pClkFreqs->ClockType = 0;					/* Current clocks */
    pClkFreqs->reserved = 0;					/* These bits are reserved for future use. Must be set to 0. */
    pClkFreqs->domain[0].bIsPresent = 1;
    pClkFreqs->domain[0].frequency = (gpu * 1000);		/* Core clock */
    pClkFreqs->domain[4].bIsPresent = 1;
    pClkFreqs->domain[4].frequency = (memclk * 1000);		/* Memory clock (DDR type clock) */
    return NVAPI_OK;
}

/* Experimenting with "CurrentpState" */
static NvAPI_Status CDECL NvAPI_GPU_GetCurrentPstate(NvPhysicalGpuHandle hPhysicalGPU, NvU32 *pCurrentPstate)
{
    TRACE("(%p, %p)\n", hPhysicalGPU, pCurrentPstate);

    if (hPhysicalGPU != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGPU);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    *pCurrentPstate = 0;					/* "Performance mode" pstate0 */
    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_GPU_GetPstates20(NvPhysicalGpuHandle hPhysicalGpu, NV_GPU_PERF_PSTATES20_INFO *pPstatesInfo)
{
    TRACE("(%p, %p)\n", hPhysicalGpu, pPstatesInfo);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    get_nv_clocks();
    int gpu=(clocks >> 16);
    short memclk=clocks;
    pPstatesInfo->numPstates = 1;
    pPstatesInfo->numClocks = 1;
    pPstatesInfo->numBaseVoltages = 1;
    pPstatesInfo->pstates[0].pstateId = 0;			/* Hopefully "Performance mode" */
    pPstatesInfo->pstates[0].reserved = 0;			/* These bits are reserved for future use (must be always 0) ref. NV Docs */
    pPstatesInfo->pstates[0].clocks[0] = 1;			/* Enable clock? */
    pPstatesInfo->pstates[0].clocks[7] = (gpu * 1000);		/* Current GPU clock? */
    pPstatesInfo->pstates[0].baseVoltages[0] = 1;
    pPstatesInfo->pstates[1].pstateId = 0;
    pPstatesInfo->pstates[1].reserved = 0;			/* These bits are reserved for future use (must be always 0) ref. NV Docs */
    pPstatesInfo->pstates[1].clocks[0] = 1;			/* Enable clock */
    pPstatesInfo->pstates[1].clocks[3] = (memclk * 1000);	/* Current VRAM clock */
    return NVAPI_OK;
}

static int get_gpu_usage(void)
{
    if (!(display = XOpenDisplay(NULL))) {
                TRACE("(%p)\n", XDisplayName(NULL));
                return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
    }
    Bool gpu_load=XNVCTRLQueryTargetStringAttribute(display,
                                                NV_CTRL_TARGET_TYPE_GPU,
                                                0, // target_id
                                                0, // display_mask
                                                NV_CTRL_STRING_GPU_UTILIZATION,
                                                &gfxload);
    XCloseDisplay(display);
    if (!gpu_load) {
            FIXME("invalid display: %s\n", gfxload);
            return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
        }
    return (gpu_load);
}

/* GPU Usage */
static NvAPI_Status CDECL NvAPI_GPU_GetUsages(NvPhysicalGpuHandle hPhysicalGpu, NV_USAGES_INFO *pUsagesInfo)
{
    TRACE("(%p, %p)\n", hPhysicalGpu, pUsagesInfo);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }

    get_gpu_usage();								/* NVCtrl output a string with usages */
    char *gpuuse = strtok_r(gfxload, ",", &gfxload);				/* Conversion */
    memmove(gpuuse, gpuuse+9, strlen(gpuuse));					/* Magic      */
    pUsagesInfo->flags = 1;
    pUsagesInfo->usages[0].bIsPresent = 1;
    pUsagesInfo->usages[0].percentage[0] = strtoul(gpuuse, &gpuuse, 10);	/* This is GPU usage % */
    char *memuse = strtok_r(gfxload, ",", &gfxload);				/* Conversion */
    memmove(memuse, memuse+8, strlen(memuse));					/* Magic      */
    pUsagesInfo->usages[0].percentage[4] = strtoul(memuse, &memuse, 10);	/* This is Memory controller usage % */
    return NVAPI_OK;
}

/* GPU Type - Discrete */
static NvAPI_Status CDECL NvAPI_GPU_GetGPUType(NvPhysicalGpuHandle hPhysicalGpu, NvU32 *pGpuType)
{
    TRACE("(%p, %p)\n", hPhysicalGpu, pGpuType);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    *pGpuType = 2; 							/* Discrete GPU Type */
    return NVAPI_OK;
}

/* GPU Memory bandwidth and Location */
static NvAPI_Status CDECL NvAPI_GPU_GetFBWidthAndLocation(NvPhysicalGpuHandle hPhysicalGpu, NvU32* pWidth, NvU32* pLocation)
{
    int bwidth;
    TRACE("(%p, %p, %p)\n", hPhysicalGpu, pWidth, pLocation);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    if (!(display = XOpenDisplay(NULL))) {
                TRACE("(%p)\n", XDisplayName(NULL));
		return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
    }
    *pLocation = 0;						/* Unsure what this value indicates "onboard"? */
    Bool buswidth=XNVCTRLQueryAttribute(display,0,0, NV_CTRL_GPU_MEMORY_BUS_WIDTH, &bwidth);
    XCloseDisplay(display);
    if (!buswidth) {
            FIXME("invalid display: %d\n", bwidth);
            return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    *pWidth = bwidth;
    return NVAPI_OK;
}

/* Get GPU load in "Performance mode" */
static NvAPI_Status CDECL NvAPI_GPU_GetDynamicPstatesInfoEx(NvPhysicalGpuHandle hPhysicalGpu, NV_GPU_DYNAMIC_PSTATES_INFO_EX *pDynamicPstatesInfoEx)
{
    TRACE("(%p, %p)\n", hPhysicalGpu, pDynamicPstatesInfoEx);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    get_gpu_usage();							/* Get string of usages from NVCtrl */
    char *result = strtok_r(gfxload, ",", &gfxload);
    memmove(result, result+9, strlen(result));
    pDynamicPstatesInfoEx->flags = 1;
    pDynamicPstatesInfoEx->utilization[0].bIsPresent = 1;
    pDynamicPstatesInfoEx->utilization[0].percentage = strtoul(result, &result, 10);
    return NVAPI_OK;
}

/* Get Core Volt */
static NvAPI_Status CDECL NvAPI_GPU_GetVoltageDomainsStatus(NvPhysicalGpuHandle hPhysicalGpu, NV_VOLT_STATUS *pVoltStatus)
{
    int corevolt;
    TRACE("(%p, %p)\n", hPhysicalGpu, pVoltStatus);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    if (!(display = XOpenDisplay(NULL))) {
                TRACE("(%p)\n", XDisplayName(NULL));
		return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
    }
    Bool gpuvolt=XNVCTRLQueryAttribute(display,0,0, NV_CTRL_GPU_CURRENT_CORE_VOLTAGE, &corevolt);
    XCloseDisplay(display);
    if (!gpuvolt) {
            FIXME("invalid display: %d\n", corevolt);
            return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    pVoltStatus->flags = 0;
    pVoltStatus->count = 1;
    pVoltStatus->value_uV = corevolt;
    pVoltStatus->buf1 = 1;
    return NVAPI_OK;
}

/* Fakes "Desktop" SystemType */
static NvAPI_Status CDECL NvAPI_GPU_GetSystemType(NvPhysicalGpuHandle hPhysicalGPU, NvU32 *pSystemType)
{
    TRACE("(%p, %p)\n", hPhysicalGPU, pSystemType);

    if (hPhysicalGPU != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGPU);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }

    *pSystemType = 2;
    return NVAPI_OK;
}

/* Get nVidia BIOS Version from NVCtrl */
static NvAPI_Status CDECL NvAPI_GPU_GetVbiosVersionString(NvPhysicalGpuHandle hPhysicalGPU, NvAPI_ShortString szBiosRevision)
{
    char *biosver;
    TRACE("(%p, %p)\n", hPhysicalGPU, szBiosRevision);

    if (!hPhysicalGPU)
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;

    if (hPhysicalGPU != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid argument: %p\n", hPhysicalGPU);
        return NVAPI_INVALID_ARGUMENT;
    }
    if (!(display = XOpenDisplay(NULL))) {
        TRACE("(%p)\n", XDisplayName(NULL));
        return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
    }
    Bool biosv=XNVCTRLQueryTargetStringAttribute(display,
                                                NV_CTRL_TARGET_TYPE_GPU,
                                                0, // target_id
                                                0, // display_mask
                                                NV_CTRL_STRING_VBIOS_VERSION,
                                                &biosver);
    XCloseDisplay(display);
    if (!biosv) {
        return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
    }

    strcpy(szBiosRevision, biosver);
    if (!szBiosRevision)
      return NVAPI_INVALID_ARGUMENT;

    return NVAPI_OK;
}

/* Get device IRQ from NVCtrl */
static NvAPI_Status CDECL NvAPI_GPU_GetIRQ(NvPhysicalGpuHandle hPhysicalGPU, NvU32 *pIRQ)
{
    int gpuirq;
    TRACE("(%p, %p)\n", hPhysicalGPU, pIRQ);

    if (hPhysicalGPU != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGPU);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    if (!(display = XOpenDisplay(NULL))) {
                TRACE("(%p)\n", XDisplayName(NULL));
                return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
    }
    Bool irqgpu=XNVCTRLQueryAttribute(display,0,0, NV_CTRL_IRQ, &gpuirq);
    XCloseDisplay(display);
    if (!irqgpu) {
            FIXME("invalid display: %d\n", gpuirq);
            return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    *pIRQ = gpuirq;
    if (!pIRQ)
      return NVAPI_INVALID_ARGUMENT;

    return NVAPI_OK;
}

/* Get device and vendor id from NVCtrl to create NVAPI PCI ID's */
static NvAPI_Status CDECL NvAPI_GPU_GetPCIIdentifiers(NvPhysicalGpuHandle hPhysicalGPU, NvU32 *pDeviceId, NvU32 *pSubSystemId, NvU32 *pRevisionId, NvU32 *pExtDeviceId)
{
    int pciid;
    TRACE("(%p, %p, %p, %p, %p)\n", hPhysicalGPU, pDeviceId, pSubSystemId, pRevisionId, pExtDeviceId);

    if (hPhysicalGPU != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGPU);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    if (!(display = XOpenDisplay(NULL))) {
                TRACE("(%p)\n", XDisplayName(NULL));
		return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
    }
    /* Grab Device and vendor ID string from NVCtrl */
    Bool id=XNVCTRLQueryTargetAttribute(display, NV_CTRL_TARGET_TYPE_GPU, 0, 0, NV_CTRL_PCI_ID, &pciid);
    XCloseDisplay(display);
    if (!id) {
            FIXME("invalid display: %d\n", pciid);
            return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    /* Need to swap high/low word in the ID from NVCtrl to satisfy NVAPI */
    uint ven=(pciid >> 16);
    short dev=pciid;
    uint32_t devid=(uint32_t) dev << 16 | ven;
    *pDeviceId = devid; 				/* Final device and vendor ID */
    *pSubSystemId = 828380258; 				/* MSI board maker - NVCtrl does not have this, so fake it */
    *pRevisionId = 161;
    *pExtDeviceId = 0;
    return NVAPI_OK;
}

/* Fake Fan Speed */
static NvAPI_Status CDECL NvAPI_GPU_GetTachReading(NvPhysicalGpuHandle hPhysicalGPU, NvU32 *pValue)
{
    int fanspeed;
    TRACE("(%p, %p)\n", hPhysicalGPU,  pValue);

    if (hPhysicalGPU != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGPU);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    if (!(display = XOpenDisplay(NULL))) {
        TRACE("(%p)\n", XDisplayName(NULL));
        return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
    }
    Bool fanstatus=XNVCTRLQueryTargetAttribute(display,
                          NV_CTRL_TARGET_TYPE_COOLER,
                          0, // target_id
                          0, // display_mask
                          NV_CTRL_THERMAL_COOLER_CURRENT_LEVEL,
                          &fanspeed);
    XCloseDisplay(display);
    if (!fanstatus) {
        FIXME("invalid result: %d\n", fanspeed);
        return NVAPI_NOT_SUPPORTED;
    }
    /* The value above is in % fan speed. Assuming average fan RPM is 2300 rpm we calculate */
    /* This value depends on manufacturer, but can be checked with Linux nVidia control panel */
    *pValue = (fanspeed * 23);		/* Result is 23 x % - eg: 100% = 2300 */
    if (!pValue)
      return NVAPI_NOT_SUPPORTED;

    return NVAPI_OK;
}

/* Get GPU temperature from NVCtrl */
static int get_gpu_temp(void)
{
    if (!(display = XOpenDisplay(NULL))) {
                TRACE("(%p)\n", XDisplayName(NULL));
		return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
    }
    Bool gpu_temp=XNVCTRLQueryAttribute(display,0,0, NV_CTRL_GPU_CORE_TEMPERATURE, &gputemp);
    XCloseDisplay(display);
    if (!gpu_temp) {
            FIXME("invalid display: %d\n", gputemp);
            return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
        }
    return (gpu_temp);
}

/* NVCtrl slowdown temp threshold */
static int get_gpu_maxtemp(void)
{
    if (!(display = XOpenDisplay(NULL))) {
                TRACE("(%p)\n", XDisplayName(NULL));
                return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
    }
    Bool gpu_maxtemp=XNVCTRLQueryAttribute(display,0,0, NV_CTRL_GPU_MAX_CORE_THRESHOLD, &gpumaxtemp);
    XCloseDisplay(display);
    if (!gpu_maxtemp) {
            FIXME("invalid display: %d\n", gpumaxtemp);
            return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
        }
    return (gpu_maxtemp);
}

/* Thermal Settings - GPU Temp */
static NvAPI_Status CDECL NvAPI_GPU_GetThermalSettings(NvPhysicalGpuHandle hPhysicalGpu, NvU32 sensorIndex, NV_GPU_THERMAL_SETTINGS *pThermalSettings)
{
    TRACE("(%p, %p)\n", hPhysicalGpu,  pThermalSettings);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }

    sensorIndex = 0;
    pThermalSettings->count = 1;
    pThermalSettings->sensor[0].controller = 1; /* Gpu_Internal */
    pThermalSettings->sensor[0].defaultMinTemp = 0;
    pThermalSettings->sensor[0].defaultMaxTemp = (get_gpu_maxtemp(), gpumaxtemp);	/* GPU max temp threshold */
    pThermalSettings->sensor[0].currentTemp = (get_gpu_temp(), gputemp); 		/* Current GPU Temp */
    pThermalSettings->sensor[0].target = 1;						/* GPU */
    pThermalSettings->sensor[1].controller = 1;						/* Gpu_Internal */
    pThermalSettings->sensor[1].defaultMinTemp = 0;
    pThermalSettings->sensor[1].defaultMaxTemp = 40;
    pThermalSettings->sensor[1].currentTemp = 25;					/* "Fake" Memory Temp */
    pThermalSettings->sensor[1].target = 2;						/* Memory */
    return NVAPI_OK;
}

/* NvAPI Version String */
static NvAPI_Status CDECL NvAPI_GetInterfaceVersionString(NvAPI_ShortString szDesc)
{
    NvAPI_ShortString version = {'1','7','3','5',0};

    TRACE("(%p)\n", szDesc);

    memcpy(szDesc, version, sizeof(version));
    return NVAPI_OK;
}

/* Nvidia GPU BusID */
static NvAPI_Status CDECL NvAPI_GPU_GetBusId(NvPhysicalGpuHandle hPhysicalGpu, NvU32 *pBusId)
{
    int pcibus;
    TRACE("(%p, %p)\n", hPhysicalGpu,  pBusId);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }

    if (!(display = XOpenDisplay(NULL))) {
                TRACE("(%p)\n", XDisplayName(NULL));
		return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
    }
    /* Get PCI_BUS_ID from NVCtrl */
    Bool bus=XNVCTRLQueryTargetAttribute(display, NV_CTRL_TARGET_TYPE_GPU, 0, 0, NV_CTRL_PCI_BUS, &pcibus);
    XCloseDisplay(display);
    if (!bus) {
            FIXME("invalid display: %d\n", pcibus);
            return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    *pBusId = (uint)pcibus;

    if (!pBusId)
      return NVAPI_INVALID_ARGUMENT;

    return NVAPI_OK;
}

/* Shader Pipe Count (Se note below) */
static NvAPI_Status CDECL NvAPI_GPU_GetShaderPipeCount(NvPhysicalGpuHandle hPhysicalGpu, NvU32 *pShaderPipeCount)
{
    int numpipes;
    TRACE("(%p, %p)\n", hPhysicalGpu,  pShaderPipeCount);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    /* NVCtrl NV_CTRL_GPU_CORES seems to provide number of "cores" available */
    if (!(display = XOpenDisplay(NULL))) {
                TRACE("(%p)\n", XDisplayName(NULL));
		return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
    }
    Bool pipecores=XNVCTRLQueryAttribute(display,0,0, NV_CTRL_GPU_CORES, &numpipes);
    XCloseDisplay(display);
    if (!pipecores) {
            FIXME("invalid display: %d\n", numpipes);
            return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }

    *pShaderPipeCount = numpipes;
    if (!pShaderPipeCount)
      return NVAPI_INVALID_ARGUMENT;

    return NVAPI_OK;
}

/* Uncertain of the difference between shader pipe and shader unit on GTX970.
   "Shader Units" = NVCtrl GPU_CORES ?				*/
static NvAPI_Status CDECL NvAPI_GPU_GetShaderSubPipeCount(NvPhysicalGpuHandle hPhysicalGpu, NvU32 *pCount)
{
    int numunits;
    TRACE("(%p, %p)\n", hPhysicalGpu,  pCount);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    if (!(display = XOpenDisplay(NULL))) {
                TRACE("(%p)\n", XDisplayName(NULL));
                return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
    }
    Bool shaderunits=XNVCTRLQueryAttribute(display,0,0, NV_CTRL_GPU_CORES, &numunits);
    XCloseDisplay(display);
    if (!shaderunits) {
            FIXME("invalid display: %d\n", numunits);
            return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    *pCount = numunits;
    if (!pCount)
      return NVAPI_INVALID_ARGUMENT;

    return NVAPI_OK;
}

/* GPU BusSlotID */
static NvAPI_Status CDECL NvAPI_GPU_GetBusSlotId(NvPhysicalGpuHandle hPhysicalGpu, NvU32 *pBusSlotId)
{
    TRACE("(%p, %p)\n", hPhysicalGpu,  pBusSlotId);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }

    *pBusSlotId = 0;

    return NVAPI_OK;
}

/* Get ram from NVCtrl */
static int get_nv_vram(void)
{
    if (!(display = XOpenDisplay(NULL))) {
                TRACE("(%p)\n", XDisplayName(NULL));
		return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
    }
    Bool nv_vram=XNVCTRLQueryAttribute(display,0,0, NV_CTRL_VIDEO_RAM, &gpuvram);
    XCloseDisplay(display);
    if (!nv_vram) {
            FIXME("invalid display: %d\n", gpuvram);
            return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
        }
    return (nv_vram);
}

/* Another Memory return function */
static NvAPI_Status CDECL NvAPI_GPU_GetMemoryInfo(NvPhysicalGpuHandle hPhysicalGpu, NV_DISPLAY_DRIVER_MEMORY_INFO *pMemoryInfo)
{
    int dedram, usedvram;
    TRACE("(%p, %p)\n", hPhysicalGpu, pMemoryInfo);

    if (!hPhysicalGpu)
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;

    get_nv_vram();								/* Get total vram */
    if (!(display = XOpenDisplay(NULL))) {
                TRACE("(%p)\n", XDisplayName(NULL));
		return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
    }
    Bool mem=XNVCTRLQueryTargetAttribute(display, NV_CTRL_TARGET_TYPE_GPU, 0, 0, NV_CTRL_TOTAL_DEDICATED_GPU_MEMORY, &dedram);
    if (!mem) {
            FIXME("invalid display: %d\n", dedram);
            return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
        }
    pMemoryInfo->dedicatedVideoMemory = gpuvram;				/* Report dedicated as total vram */
    pMemoryInfo->availableDedicatedVideoMemory = dedram * 1024;			/* Get available dedicated vram in kb */
    pMemoryInfo->sharedSystemMemory = dedram * 2048;				/* 2 x dedicated vram in kb */
    Bool memused=XNVCTRLQueryTargetAttribute(display, NV_CTRL_TARGET_TYPE_GPU, 0, 0, NV_CTRL_USED_DEDICATED_GPU_MEMORY, &usedvram);
    if (!memused) {
            FIXME("invalid display: %d\n", usedvram);
            return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
        }
    XCloseDisplay(display);
    pMemoryInfo->curAvailableDedicatedVideoMemory = (dedram - usedvram) * 1024;		/* Dedicated memory usage in kb */

    if (!pMemoryInfo)
        return NVAPI_INVALID_ARGUMENT;

    return NVAPI_OK;
}

/* Set "RamType" to GDDR5 */
static NvAPI_Status CDECL NvAPI_GPU_GetRamType(NvPhysicalGpuHandle hPhysicalGpu, NvU32 *pRamType)
{
    TRACE("(%p, %p)\n", hPhysicalGpu, pRamType);

    if (!hPhysicalGpu)
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;

    *pRamType = 8;
    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_D3D_GetObjectHandleForResource(IUnknown *pDevice, IUnknown *pResource, NVDX_ObjectHandle *pHandle)
{
    FIXME("(%p, %p, %p): stub\n", pDevice, pResource, pHandle);
    return NVAPI_ERROR;
}

static NvAPI_Status CDECL NvAPI_D3D9_RegisterResource(IDirect3DResource9* pResource)
{
    FIXME("(%p): stub\n", pResource);
    return NVAPI_ERROR;
}

static NvAPI_Status CDECL NvAPI_GPU_GetPCIEInfo(void)
{
    TRACE("()\n");
    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_GPU_GetShortName(void)
{
    TRACE("()\n");
    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_GetPhysicalGPUFromDisplay(void)
{
    TRACE("()\n");
    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_GPU_PhysxQueryRecommendedState(void)
{
    TRACE("()\n");
    return NVAPI_OK;
}

/* Deprecated */
static NvAPI_Status CDECL NvAPI_GPU_GetAllClocks(void)
{
    TRACE("()\n");
    return NVAPI_INVALID_ARGUMENT;
}

static NvAPI_Status CDECL NvAPI_GPU_GetManufacturingInfo(void)
{
    TRACE("()\n");
    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_GPU_GetTargetID(void)
{
    TRACE("()\n");
    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_GPU_GetPhysicalFrameBufferSize(NvPhysicalGpuHandle hPhysicalGpu, NvU32 *pSize)
{
    TRACE("(%p, %p)\n", hPhysicalGpu, pSize);

    if (!hPhysicalGpu)
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }

    if (!pSize)
        return NVAPI_NVIDIA_DEVICE_NOT_FOUND;

    get_nv_vram();
    *pSize = gpuvram;
    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_GPU_GetVirtualFrameBufferSize(NvPhysicalGpuHandle hPhysicalGpu, NvU32 *pSize)
{
    TRACE("(%p, %p)\n", hPhysicalGpu, pSize);

    if (!hPhysicalGpu)
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }

    get_nv_vram();
    *pSize = gpuvram * 2;		/* Somewhat safe to assume "virtual" framebuffer is 2 x vram */

    if (!pSize)
        return NVAPI_NVIDIA_DEVICE_NOT_FOUND;

    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_GPU_GetGpuCoreCount(NvPhysicalGpuHandle hPhysicalGpu, NvU32 *pCount)
{
    int numcores;
    TRACE("(%p, %p)\n", hPhysicalGpu, pCount);

    if (!hPhysicalGpu)
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }

    /* NVCtrl NV_CTRL_GPU_CORES seems to provide number of "cores" available */
    if (!(display = XOpenDisplay(NULL))) {
                TRACE("(%p)\n", XDisplayName(NULL));
                return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
    }
    Bool gpucores=XNVCTRLQueryAttribute(display,0,0, NV_CTRL_GPU_CORES, &numcores);
    XCloseDisplay(display);
    if (!gpucores) {
            FIXME("invalid display: %d\n", numcores);
            return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    *pCount = numcores;
    if (!pCount)
        return NVAPI_NVIDIA_DEVICE_NOT_FOUND;

    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_D3D11_SetDepthBoundsTest(IUnknown *pDeviceOrContext, NvU32 bEnable, float fMinDepth, float fMaxDepth)
{
    struct wined3d_device *device;
    union { DWORD d; float f; } z;

    TRACE("(%p, %u, %f, %f)\n", pDeviceOrContext, bEnable, fMinDepth, fMaxDepth);

    if (!pDeviceOrContext)
        return NVAPI_INVALID_ARGUMENT;

    if (FAILED(IUnknown_QueryInterface(pDeviceOrContext, &IID_IWineD3DDevice, (void **)&device)))
    {
        ERR("Failed to get wined3d device handle!\n");
        return NVAPI_ERROR;
    }

    wined3d_mutex_lock();
    wined3d_device_set_render_state(device, WINED3D_RS_ADAPTIVETESS_X, bEnable ? WINED3DFMT_NVDB : 0);
    z.f = fMinDepth;
    wined3d_device_set_render_state(device, WINED3D_RS_ADAPTIVETESS_Z, z.d);
    z.f = fMaxDepth;
    wined3d_device_set_render_state(device, WINED3D_RS_ADAPTIVETESS_W, z.d);
    wined3d_mutex_unlock();

    return NVAPI_OK;
}

static NVAPI_DEVICE_FEATURE_LEVEL translate_feature_level(D3D_FEATURE_LEVEL level_d3d)
{
    switch (level_d3d)
    {
        case D3D_FEATURE_LEVEL_9_1:
        case D3D_FEATURE_LEVEL_9_2:
        case D3D_FEATURE_LEVEL_9_3:
            return NVAPI_DEVICE_FEATURE_LEVEL_NULL;
        case D3D_FEATURE_LEVEL_10_0:
            return NVAPI_DEVICE_FEATURE_LEVEL_10_0;
        case D3D_FEATURE_LEVEL_10_1:
            return NVAPI_DEVICE_FEATURE_LEVEL_10_1;
        case D3D_FEATURE_LEVEL_11_0:
        default:
            return NVAPI_DEVICE_FEATURE_LEVEL_11_0;
    }
}

static NvAPI_Status CDECL NvAPI_D3D11_CreateDevice(IDXGIAdapter *adapter, D3D_DRIVER_TYPE driver_type, HMODULE swrast, UINT flags,
                                                   const D3D_FEATURE_LEVEL *feature_levels, UINT levels, UINT sdk_version,
                                                   ID3D11Device **device_out, D3D_FEATURE_LEVEL *obtained_feature_level,
                                                   ID3D11DeviceContext **immediate_context, NVAPI_DEVICE_FEATURE_LEVEL *supported)
{
    D3D_FEATURE_LEVEL level;
    HRESULT hr;

    hr = D3D11CreateDevice(adapter, driver_type, swrast, flags, feature_levels, levels, sdk_version, device_out, &level, immediate_context);
    if (FAILED(hr)) return NVAPI_ERROR;
    if (obtained_feature_level) *obtained_feature_level = level;
    if (supported) *supported = translate_feature_level(level);

    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_D3D11_CreateDeviceAndSwapChain(IDXGIAdapter *adapter, D3D_DRIVER_TYPE driver_type,HMODULE swrast, UINT flags,
                                                               const D3D_FEATURE_LEVEL *feature_levels, UINT levels, UINT sdk_version,
                                                               const DXGI_SWAP_CHAIN_DESC *swapchain_desc, IDXGISwapChain **swapchain,
                                                               ID3D11Device **device_out, D3D_FEATURE_LEVEL *obtained_feature_level,
                                                               ID3D11DeviceContext **immediate_context, NVAPI_DEVICE_FEATURE_LEVEL *supported)
{
    D3D_FEATURE_LEVEL level;
    HRESULT hr;

    hr = D3D11CreateDeviceAndSwapChain(adapter, driver_type, swrast, flags, feature_levels, levels, sdk_version, swapchain_desc, swapchain,
                                       device_out, &level, immediate_context);
    if (FAILED(hr)) return NVAPI_ERROR;
    if (obtained_feature_level) *obtained_feature_level = level;
    if (supported) *supported = translate_feature_level(level);

    return NVAPI_OK;
}

void* CDECL nvapi_QueryInterface(unsigned int offset)
{
    static const struct
    {
        unsigned int offset;
        void *function;
    }
    function_list[] =
    {
        {0x0150E828, NvAPI_Initialize},
        {0xF951A4D1, NvAPI_GetDisplayDriverVersion},
        {0x5786cc6e, NvAPI_GPU_CudaEnumComputeCapableGpus},
        {0x6533ea3e, NvAPI_GetGPUIDfromPhysicalGPU},
        {0x5380ad1a, NvAPI_GetPhysicalGPUFromGPUID},
        {0x35c29134, NvAPI_GetAssociatedNvidiaDisplayHandle},
        {0x34ef9506, NvAPI_GetPhysicalGPUsFromDisplay},
        {0x2ec50c2b, NvAPI_Stereo_Disable},
        {0x348ff8e1, NvAPI_Stereo_IsEnabled},
        {0xac7e37f4, NvAPI_Stereo_CreateHandleFromIUnknown},
        {0x3a153134, NvAPI_Stereo_DestroyHandle},
        {0xf6a1ad68, NvAPI_Stereo_Activate},
        {0x2d68de96, NvAPI_Stereo_Deactivate},
        {0x1fb0bc30, NvAPI_Stereo_IsActivated},
        {0x451f2134, NvAPI_Stereo_GetSeparation},
        {0x5c069fa3, NvAPI_Stereo_SetSeparation},
        {0x239c4545, NvAPI_Stereo_Enable},
        {0xaeaecd41, NvAPI_D3D9_StretchRectEx},
        {0x48b3ea59, NvAPI_EnumLogicalGPUs},
        {0xfb9bc2ab, NvAPI_EnumLogicalGPUs_unknown},
        {0xaea3fa32, NvAPI_GetPhysicalGPUsFromLogicalGPU},
        {0xe5ac921f, NvAPI_EnumPhysicalGPUs},
        {0xceee8e9f, NvAPI_GPU_GetFullName},
        {0x33c7358c, NULL}, /* This functions seems to be optional */
        {0x593e8644, NULL}, /* This functions seems to be optional */
        {0x1e9d8a31, NvAPI_DISP_GetGDIPrimaryDisplayId},
        {0x9abdd40d, NvAPI_EnumNvidiaDisplayHandle},
        {0x2926aaad, NvAPI_SYS_GetDriverAndBranchVersion},
        {0xd22bdd7e, NvAPI_Unload},
        {0x4b708b54, NvAPI_D3D_GetCurrentSLIState},
        {0xee1370cf, NvAPI_GetLogicalGPUFromDisplay},
        {0xfceac864, NvAPI_D3D_GetObjectHandleForResource},
        {0xa064bdfc, NvAPI_D3D9_RegisterResource},
        {0x46fbeb03, NvAPI_GPU_GetPhysicalFrameBufferSize},
        {0x5a04b644, NvAPI_GPU_GetVirtualFrameBufferSize},
        {0xc7026a87, NvAPI_GPU_GetGpuCoreCount},
	{0xe3795199, NvAPI_GPU_GetPCIEInfo},
	{0xd988f0f3, NvAPI_GPU_GetShortName},
	{0x1890e8da, NvAPI_GetPhysicalGPUFromDisplay},
	{0x7a4174f4, NvAPI_GPU_PhysxQueryRecommendedState},
	{0x1bd69f49, NvAPI_GPU_GetAllClocks},
	{0xa4218928, NvAPI_GPU_GetManufacturingInfo},
	{0x35B5fd2f, NvAPI_GPU_GetTargetID},
	{0xe3640a56, NvAPI_GPU_GetThermalSettings},
	{0x57F7caac, NvAPI_GPU_GetRamType},
	{0xdcb616c3, NvAPI_GPU_GetAllClockFrequencies},
	{0xbaaabfcc, NvAPI_GPU_GetSystemType},
	{0xa561fd7d, NvAPI_GPU_GetVbiosVersionString},
	{0x2ddfb66e, NvAPI_GPU_GetPCIIdentifiers},
	{0x5f608315, NvAPI_GPU_GetTachReading},
	{0x01053fa5, NvAPI_GetInterfaceVersionString},
	{0x927da4f6, NvAPI_GPU_GetCurrentPstate},
	{0x6ff81213, NvAPI_GPU_GetPstates20},
	{0xc16c7e2c, NvAPI_GPU_GetVoltageDomainsStatus},
	{0x1be0b8e5, NvAPI_GPU_GetBusId},
	{0x2a0a350f, NvAPI_GPU_GetBusSlotId},
	{0x63e2f56f, NvAPI_GPU_GetShaderPipeCount},
	{0x0be17923, NvAPI_GPU_GetShaderSubPipeCount},
        {0x7aaf7a04, NvAPI_D3D11_SetDepthBoundsTest},
        {0x6a16d3a0, NvAPI_D3D11_CreateDevice},
        {0xbb939ee5, NvAPI_D3D11_CreateDeviceAndSwapChain},
	{0x60ded2ed, NvAPI_GPU_GetDynamicPstatesInfoEx},
	{0x07f9b368, NvAPI_GPU_GetMemoryInfo},
	{0x774aa982, NvAPI_GPU_GetMemoryInfo},
	{0xc33baeb1, NvAPI_GPU_GetGPUType},
	{0x189a1fdf, NvAPI_GPU_GetUsages},
	{0xe4715417, NvAPI_GPU_GetIRQ},
	{0x11104158, NvAPI_GPU_GetFBWidthAndLocation},
    };
    unsigned int i;
    TRACE("(%x)\n", offset);

    for (i = 0; i < sizeof(function_list) / sizeof(function_list[0]); i++)
    {
        if (function_list[i].offset == offset)
            return function_list[i].function;
    }

    return get_thunk_function(offset);
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    TRACE("(%p, %u, %p)\n", instance, reason, reserved);
    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(instance);
            init_thunks();
            break;
        case DLL_PROCESS_DETACH:
            free_thunks();
            break;
    }

    return TRUE;
}
