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
#include <stdlib.h>
#include <assert.h>
#include "Xlib.h"
#include <NVCtrl/NVCtrlLib.h>
#include <pthread.h>

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

nvapi_nvml_state g_nvml;
#if defined(__i386__) || defined(__x86_64__)

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
Display *display;

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


int nvidia_settings_query_attribute_str(const char *attribute, char **attr_value)
{
    /* These buffers *should* be long enough for most purposes */
    const int ATTR_BUFFER_SIZE = 512;
    char command[256];
    FILE *nvidia_settings = NULL;
    int nch = 0;

    nch = snprintf(command, sizeof(command), "nvidia-settings -q \"%s\" -t", attribute);
    if (nch > sizeof(command))
    {
        ERR("nvidia-settings command buffer too short!\n");
        return -1;
    }

    nvidia_settings = popen(command, "r");

    *attr_value = malloc(ATTR_BUFFER_SIZE);
    nch = fread(*attr_value, 1, ATTR_BUFFER_SIZE, nvidia_settings);
    if (nch == ATTR_BUFFER_SIZE)
    {
        ERR("nvidia-settings attr_value buffer too short!\n");
        free(*attr_value);
        *attr_value = NULL;
        return pclose(nvidia_settings);
    }

    (*attr_value)[nch] = '\0';
    return pclose(nvidia_settings);
}

int nvidia_settings_query_attribute_int(const char *attribute, int *attr_value)
{
    int retcode = 0;
    char *str_value = NULL;

    retcode = nvidia_settings_query_attribute_str(attribute, &str_value);

    if (retcode == 0)
        *attr_value = atoi(str_value);

    if (str_value)
        free(str_value);

    return retcode;
}

static int get_video_memory_total(void)
{
    static nvmlMemory_t memory = { 0 };
    nvmlReturn_t rc = NVML_SUCCESS;

    if (memory.total)
        return memory.total / 1024;

    rc = nvmlDeviceGetMemoryInfo(g_nvml.device, &memory);
    if (rc != NVML_SUCCESS)
        TRACE("XNVCTRLQueryTargetAttribute(NV_CTRL_TOTAL_DEDICATED_GPU_MEMORY) failed!\n");

    if (memory.total == 0)
        memory.total = 1024 * 1024 * 1024; /* fallback: 1GB */

    return memory.total / 1024;
}

static int get_video_memory_free(void)
{
    static nvmlMemory_t memory = { 0 };
    nvmlReturn_t rc = NVML_SUCCESS;

    if (memory.free)
        return memory.free / 1024;

    rc = nvmlDeviceGetMemoryInfo(g_nvml.device, &memory);
    if (rc != NVML_SUCCESS)
        TRACE("XNVCTRLQueryTargetAttribute(NV_CTRL_TOTAL_DEDICATED_GPU_MEMORY) failed!\n");

    if (memory.free == 0)
        memory.free = 1024 * 1024 * 1024; /* fallback: 1GB */

    return memory.free / 1024;
}

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

static int open_disp(void)
{
    pthread_mutex_lock(&mutex);
    if (!(display = XOpenDisplay(NULL))) {
        TRACE("(%p)\n", XDisplayName(NULL));
        return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
    }
    return 0;
}

static int close_disp(void)
{
    XCloseDisplay(display);
    pthread_mutex_unlock(&mutex);
    return 0;
}

static NvAPI_Status CDECL NvAPI_GetDisplayDriverVersion(NvDisplayHandle hNvDisplay, NV_DISPLAY_DRIVER_VERSION *pVersion)
{
    nvmlReturn_t rc = NVML_SUCCESS;
    char version[16];
    char szName[NVAPI_SHORT_STRING_MAX];
    TRACE("(%p, %p)\n", hNvDisplay, pVersion);

    if (hNvDisplay && hNvDisplay != FAKE_DISPLAY)
    {
        FIXME("invalid display handle: %p\n", hNvDisplay);
        return NVAPI_INVALID_HANDLE;
    }

    /* Return driver version */
    pVersion->version = NV_DISPLAY_DRIVER_VERSION_VER;
    pVersion->bldChangeListNum = 0;
    rc = nvmlSystemGetDriverVersion(version, 16);               /* Get driver version */
    if (rc != NVML_SUCCESS) {
        WARN("invalid driver version!\n");
        return NVAPI_INVALID_POINTER;
    }
    else
    {
    char branch[16];
    char *ptr;
    char build_str[16] = { 'r', '0', '_', '0', '0', '\0' };	/* Empty "branch" string		*/
    strcpy(branch, version);
    /* Trunkate driver version to remove delimiter */
    strcpy(&version[3], &version[3 + 1]);
    pVersion->drvVersion = strtoul(version, &ptr, 10);		/* Short driver version string		*/
    /* Create "branch" version */
    strcpy(&branch[2], &branch[10]);				/* Get "major" version			*/
    branch[2] = '\0';                                           /*  Teminate buffer.. or something      */
    lstrcpynA(pVersion->szBuildBranchString, build_str, 2);	/*					*/
    pVersion->szBuildBranchString[1] = '\0';			/* End string				*/
    strcat(pVersion->szBuildBranchString, branch);		/* Creates Rxx0_00 version		*/
    strcat(pVersion->szBuildBranchString, build_str + 1); 	/* Final branch version from NvAPI	*/
    }
    /* Get Adaptername from nvml */
    rc = nvmlDeviceGetName(g_nvml.device, szName, NVAPI_SHORT_STRING_MAX);
    if (rc != NVML_SUCCESS)
    {
        ERR("nvml: could not get device name: error %u\n", rc);
        return NVAPI_ERROR;
    }
    else
    {
    strcpy(pVersion->szAdapterString, szName);			/* Report adapter name from nvml */
    }
    if (!pVersion)
        return NVAPI_INVALID_ARGUMENT;
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
    nvmlReturn_t rc = NVML_SUCCESS;

    if (!hPhysicalGpu)
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_INVALID_HANDLE;
    }

    if (!szName)
        return NVAPI_INVALID_ARGUMENT;

    rc = nvmlDeviceGetName(g_nvml.device, szName, NVAPI_SHORT_STRING_MAX);
    if (rc != NVML_SUCCESS)
    {
        ERR("nvml: could not get device name: error %u\n", rc);
        return NVAPI_ERROR;
    }

    TRACE("(%p, %p) -> \"%s\"\n", hPhysicalGpu, szName, szName);

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
static NvAPI_Status CDECL NvAPI_SYS_GetDriverAndBranchVersion(NvU32 *pDriverVersion, NvAPI_ShortString szBuildBranchString)
{
    nvmlReturn_t rc = NVML_SUCCESS;
    char version[16];
    TRACE("(%p, %p)\n", pDriverVersion, szBuildBranchString);

    if (!pDriverVersion || !szBuildBranchString)
        return NVAPI_INVALID_ARGUMENT;

    /* Return driver version */
    rc = nvmlSystemGetDriverVersion(version, 16);	/* Get driver version */
    if (rc != NVML_SUCCESS) {
        WARN("invalid driver version! Error: %u\n", rc);
        return NVAPI_INVALID_POINTER;
    }
    else
    {
    char branch[16];
    char *ptr;
    char build_str[16] = { 'r', '0', '_', '0', '0', '\0' };	/* Empty "branch" string */
    strcpy(branch, version);
    /* Trunkate driver version to remove delimiter */
    strcpy(&version[3], &version[3 + 1]);
    *pDriverVersion = strtoul(version, &ptr, 10); 		/*  Short driver version string		*/
    /* Create "branch" version */
    strcpy(&branch[2], &branch[10]);	 			/*  Get "major" version			*/
    branch[2] = '\0';						/*  Teminate buffer.. or something	*/
    lstrcpynA(szBuildBranchString, build_str, 2);		/*					*/
    szBuildBranchString[1] = '\0';				/*  End string				*/
    strcat(szBuildBranchString, branch);			/*  Creates Rxx0_00 version		*/
    strcat(szBuildBranchString, build_str + 1);			/*  Final branch version from NvAPI	*/
    /* Assumption: 415.22.05 is from the R410 driver "branch" (Not verified) */
    }
    return NVAPI_OK;
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

/* Simulate getting active 3D apps */
static NvAPI_Status CDECL NvAPI_GPU_QueryActiveApps(NvDisplayHandle hNvDisp, NV_ACTIVE_APP *pActiveApps, NvU32 *pTotal)
{
    TRACE("(%p, %p, %p)\n", hNvDisp, pActiveApps, pTotal);
    if (hNvDisp && hNvDisp != FAKE_DISPLAY)
        return NVAPI_NVIDIA_DEVICE_NOT_FOUND;
    pActiveApps[0].processPID = 1000;				/* Fake PID of app			*/
    strcpy(pActiveApps[0].processName, "Wine Desktop.exe");	/* Fake appname				*/
    *pTotal = 1;						/* Total number of active 3D apps	*/
    return NVAPI_OK;
}

/* Get GPU/MEM clocks from NVml */
static NvAPI_Status CDECL NvAPI_GPU_GetAllClockFrequencies(NvPhysicalGpuHandle hPhysicalGPU, NV_GPU_CLOCK_FREQUENCIES *pClkFreqs)
{
    nvmlReturn_t rc = NVML_SUCCESS;
    nvmlClockId_t clockId = NVML_CLOCK_ID_CURRENT;
    int clock = 0;
    unsigned int clock_MHz = 0;
    TRACE("(%p, %p)\n", hPhysicalGPU, pClkFreqs);

    if (hPhysicalGPU != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGPU);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }

    if (!pClkFreqs)
        return NVAPI_INVALID_ARGUMENT;

    for (clock = 0; clock < NVAPI_MAX_GPU_PUBLIC_CLOCKS; ++clock)
    {
        pClkFreqs->domain[clock].bIsPresent = 0;
        pClkFreqs->domain[clock].frequency = 0;
    }

    /* Version 1 is always the "current" clock */
    if (pClkFreqs->version == NV_GPU_CLOCK_FREQUENCIES_VER_2 ||
        pClkFreqs->version == NV_GPU_CLOCK_FREQUENCIES_VER_3)
    {
        switch (pClkFreqs->ClockType) {
            case NV_GPU_CLOCK_FREQUENCIES_CURRENT_FREQ:
                clockId = NVML_CLOCK_ID_CURRENT;
                break;
            case NV_GPU_CLOCK_FREQUENCIES_BASE_CLOCK:
                clockId = NVML_CLOCK_ID_APP_CLOCK_DEFAULT;
                break;
            case NV_GPU_CLOCK_FREQUENCIES_BOOST_CLOCK:
                clockId = NVML_CLOCK_ID_CUSTOMER_BOOST_MAX;
                break;
        }
    }

    rc = nvmlDeviceGetClock(g_nvml.device, NVML_CLOCK_GRAPHICS, clockId, &clock_MHz);
    if (rc != NVML_SUCCESS)
    {
        WARN("NVML failed to query graphics clock: error %u\n", rc);
    }
    else
    {
        pClkFreqs->domain[NVAPI_GPU_PUBLIC_CLOCK_GRAPHICS].bIsPresent = TRUE;
        pClkFreqs->domain[NVAPI_GPU_PUBLIC_CLOCK_GRAPHICS].frequency = clock_MHz * 1000;
        TRACE("Graphics clock: %u MHz\n", clock_MHz);
    }

    rc = nvmlDeviceGetClock(g_nvml.device, NVML_CLOCK_MEM, clockId, &clock_MHz);
    if (rc != NVML_SUCCESS)
    {
        WARN("NVML failed to query memory clock: error %u\n", rc);
    }
    else
    {
        pClkFreqs->domain[NVAPI_GPU_PUBLIC_CLOCK_MEMORY].bIsPresent = TRUE;
        pClkFreqs->domain[NVAPI_GPU_PUBLIC_CLOCK_MEMORY].frequency = clock_MHz * 1000;
        TRACE("Memory clock: %u MHz\n", clock_MHz);
    }

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
    nvmlReturn_t rc = NVML_SUCCESS;
    nvmlClockId_t clockId = NVML_CLOCK_ID_CURRENT;
    unsigned int clock_MHz = 0;
    TRACE("(%p, %p)\n", hPhysicalGpu, pPstatesInfo);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    if (!pPstatesInfo)
        return NVAPI_INVALID_ARGUMENT;

    pPstatesInfo->version = NV_GPU_PERF_PSTATES20_INFO_VER2;
    pPstatesInfo->numPstates = 1;
    pPstatesInfo->numClocks = 1;
    pPstatesInfo->numBaseVoltages = 1;
    pPstatesInfo->pstates[0].pstateId = 0;					/* Pstate-0 "Performance" */
    pPstatesInfo->pstates[0].reserved = 0;					/* These bits are reserved for future use (must be always 0) ref. NV Docs */
    pPstatesInfo->ov.numVoltages = 1;

    rc = nvmlDeviceGetClock(g_nvml.device, NVML_CLOCK_GRAPHICS, clockId, &clock_MHz);
    if (rc != NVML_SUCCESS)
    {
        WARN("NVML failed to query graphics clock: error %u\n", rc);
    }
    else
    {
    pPstatesInfo->pstates[0].clocks[0].data.range.maxFreq_kHz = (clock_MHz * 1000);	/* "current" gpu clock */
    pPstatesInfo->pstates[0].clocks[0].freqDelta_kHz.value = 0;				/* "OC" gpu clock - set to 0 for no OC */
    TRACE("Graphics clock: %u MHz\n", clock_MHz);
    }

    rc = nvmlDeviceGetClock(g_nvml.device, NVML_CLOCK_MEM, clockId, &clock_MHz);
    if (rc != NVML_SUCCESS)
    {
        WARN("NVML failed to query memory clock: error %u\n", rc);
    }
    else
    {
    pPstatesInfo->pstates[0].clocks[1].data.single.freq_kHz = (clock_MHz * 1000);	/* "current" memory clock */
    pPstatesInfo->pstates[0].clocks[1].freqDelta_kHz.value = 0;				/* "OC" memory clock - set to 0 for no OC */
    TRACE("Memory clock: %u MHz\n", clock_MHz);
    }

    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_GPU_GetPstatesInfo(NvPhysicalGpuHandle hPhysicalGpu, NV_GPU_PERF_PSTATES_INFO *pPstatesInfo)
{
    nvmlReturn_t rc = NVML_SUCCESS;
    nvmlClockId_t clockId = NVML_CLOCK_ID_CURRENT;
    unsigned int clock_MHz = 0;
    TRACE("(%p, %p)\n", hPhysicalGpu, pPstatesInfo);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    if (!pPstatesInfo)
        return NVAPI_INVALID_ARGUMENT;

    pPstatesInfo->version = NV_GPU_PERF_PSTATES_INFO_V2_VER;
    pPstatesInfo->flags = 1;					/* Reserved */
    pPstatesInfo->numPstates = 1;
    pPstatesInfo->numClocks = 2;
    pPstatesInfo->numVoltages = 1;
    pPstatesInfo->pstates[0].pstateId = 0;			/* Pstate-0 "Performance" */
    pPstatesInfo->pstates[0].flags = 0;

    rc = nvmlDeviceGetClock(g_nvml.device, NVML_CLOCK_GRAPHICS, clockId, &clock_MHz);
    if (rc != NVML_SUCCESS)
    {
        WARN("NVML failed to query graphics clock: error %u\n", rc);
    }
    else
    {
    pPstatesInfo->pstates[0].clocks[0].domainId = NVML_CLOCK_GRAPHICS;	/* Gpu clock */
    pPstatesInfo->pstates[0].clocks[0].flags = 1;
    pPstatesInfo->pstates[0].clocks[0].freq = (clock_MHz * 1000);	/* GPU clock */
    TRACE("Graphics clock: %u MHz\n", clock_MHz);
    }

    rc = nvmlDeviceGetClock(g_nvml.device, NVML_CLOCK_MEM, clockId, &clock_MHz);
    if (rc != NVML_SUCCESS)
    {
        WARN("NVML failed to query memory clock: error %u\n", rc);
    }
    else
    {
    pPstatesInfo->pstates[0].clocks[1].domainId = NVML_CLOCK_MEM;	/* Memory clock */
    pPstatesInfo->pstates[0].clocks[1].flags = 1;
    pPstatesInfo->pstates[0].clocks[1].freq = (clock_MHz * 1000);	/* Mem clock */
    TRACE("Memory clock: %u MHz\n", clock_MHz);
    }

    /* Get CORE Voltage from NVCtrl */ 
    int corevolt = 0;
    open_disp();
    Bool gpuvolt=XNVCTRLQueryAttribute(display,0,0, NV_CTRL_GPU_CURRENT_CORE_VOLTAGE, &corevolt);
    close_disp();
    if (!gpuvolt) {
            FIXME("invalid display: %d\n", corevolt);
            return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    pPstatesInfo->pstates[0].voltages[0].mvolt = (corevolt / 1000);	/* CoreVolt in mVolt */
    return NVAPI_OK;
}

/* GPU Usage */
static NvAPI_Status CDECL NvAPI_GPU_GetUsages(NvPhysicalGpuHandle hPhysicalGpu, NV_USAGES_INFO *pUsagesInfo)
{
    nvmlReturn_t rc = NVML_SUCCESS;
    nvmlUtilization_t utilization;
    TRACE("(%p, %p)\n", hPhysicalGpu, pUsagesInfo);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }

    pUsagesInfo->version = NV_USAGES_INFO_V1_VER;
    pUsagesInfo->flags = 1;
    pUsagesInfo->usages[0].bIsPresent = 1;

    rc = nvmlDeviceGetUtilizationRates(g_nvml.device, &utilization);
    if (rc != NVML_SUCCESS)
    {
        WARN("NVML failed to query utilizations: error %u\n", rc);
    }
    else
    {
    pUsagesInfo->usages[0].percentage[0] = utilization.gpu;	/* This is GPU usage % */
    pUsagesInfo->usages[0].percentage[4] = utilization.memory;	/* This is Memory controller usage % */
    TRACE("GPU utilization: %u\n", utilization.gpu);
    TRACE("Mem utilization: %u\n", utilization.memory);
    }
    return NVAPI_OK;
}

/* GPU Type - Discrete */
static NvAPI_Status CDECL NvAPI_GPU_GetGPUType(NvPhysicalGpuHandle hPhysicalGpu, NV_GPU_TYPE *pGpuType)
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
    open_disp();
    Bool buswidth=XNVCTRLQueryAttribute(display,0,0, NV_CTRL_GPU_MEMORY_BUS_WIDTH, &bwidth);
    close_disp();
    if (!buswidth) {
            FIXME("invalid display: %d\n", bwidth);
            return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    *pLocation = 1;						/* 1 = "GPU Dedicated" */
    *pWidth = bwidth;
    return NVAPI_OK;
}

/* Get PCIe "lanes" */
static NvAPI_Status CDECL NvAPI_GPU_GetCurrentPCIEDownstreamWidth(NvPhysicalGpuHandle hPhysicalGpu,NvU32 *pWidth)
{
    nvmlReturn_t rc = NVML_SUCCESS;
    unsigned int lanes;
    TRACE("(%p, %p)\n", hPhysicalGpu, pWidth);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    rc = nvmlDeviceGetCurrPcieLinkWidth(g_nvml.device, &lanes);
    if (rc != NVML_SUCCESS)
    {
        WARN("NVML failed to query PCIe lanes: error %u\n", rc);
    }
    else
    {
    *pWidth = lanes;
    }
    if (!pWidth) {
            FIXME("invalid display: %d\n", *pWidth);
            return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    return NVAPI_OK;
}

/* Get GPU load in "Performance mode" */
static NvAPI_Status CDECL NvAPI_GPU_GetDynamicPstatesInfoEx(NvPhysicalGpuHandle hPhysicalGpu, NV_GPU_DYNAMIC_PSTATES_INFO_EX *pDynamicPstatesInfoEx)
{
    nvmlReturn_t rc = NVML_SUCCESS;
    nvmlUtilization_t utilization;
    TRACE("(%p, %p)\n", hPhysicalGpu, pDynamicPstatesInfoEx);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    pDynamicPstatesInfoEx->version = NV_GPU_DYNAMIC_PSTATES_INFO_EX_VER;
    pDynamicPstatesInfoEx->flags = 1;
    pDynamicPstatesInfoEx->utilization[0].bIsPresent = 1;
    rc = nvmlDeviceGetUtilizationRates(g_nvml.device, &utilization);
    if (rc != NVML_SUCCESS)
    {
        WARN("NVML failed to query utilizations: error %u\n", rc);
    }
    else
    {
    pDynamicPstatesInfoEx->utilization[0].percentage = utilization.gpu;
    TRACE("GPU utilization: %u\n", utilization.gpu);
    }
    return NVAPI_OK;
}

/* Get Core Volt */
static NvAPI_Status CDECL NvAPI_GPU_GetVoltageDomainsStatus(NvPhysicalGpuHandle hPhysicalGpu, NV_VOLT_STATUS *pVoltStatus)
{
    int corevolt = 0;
    TRACE("(%p, %p)\n", hPhysicalGpu, pVoltStatus);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    open_disp();
    Bool gpuvolt=XNVCTRLQueryAttribute(display,0,0, NV_CTRL_GPU_CURRENT_CORE_VOLTAGE, &corevolt);
    close_disp();
    if (!gpuvolt) {
            FIXME("invalid display: %d\n", corevolt);
            return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    pVoltStatus->version = NV_VOLT_STATUS_V1_VER;
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

    *pSystemType = 2;					/* System type "2" = Desktop, "1" = Laptop */
    return NVAPI_OK;
}

/* Get nVidia BIOS Version from NVCtrl */
static NvAPI_Status CDECL NvAPI_GPU_GetVbiosVersionString(NvPhysicalGpuHandle hPhysicalGPU, NvAPI_ShortString szBiosRevision)
{
    nvmlReturn_t rc = NVML_SUCCESS;
    char version[NVML_DEVICE_INFOROM_VERSION_BUFFER_SIZE];
    TRACE("(%p, %p)\n", hPhysicalGPU, szBiosRevision);

    if (!hPhysicalGPU)
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;

    if (hPhysicalGPU != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid argument: %p\n", hPhysicalGPU);
        return NVAPI_INVALID_ARGUMENT;
    }
    if (!szBiosRevision)
      return NVAPI_INVALID_ARGUMENT;
    rc = nvmlDeviceGetVbiosVersion(g_nvml.device, version, NVML_DEVICE_INFOROM_VERSION_BUFFER_SIZE);
    if (rc != NVML_SUCCESS)
    {
        WARN("NVML failed to query bios version: error %u\n", rc);
    }
    else
    {
    strcpy(szBiosRevision, version);
    TRACE("Video BIOS version: %s\n", szBiosRevision);
    }
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
    open_disp();
    Bool irqgpu=XNVCTRLQueryAttribute(display,0,0, NV_CTRL_IRQ, &gpuirq);
    close_disp();
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
    nvmlReturn_t rc = NVML_SUCCESS;
    nvmlPciInfo_t pci;
    TRACE("(%p, %p, %p, %p, %p)\n", hPhysicalGPU, pDeviceId, pSubSystemId, pRevisionId, pExtDeviceId);

    if (hPhysicalGPU != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGPU);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    /* Grab Device and vendor ID string from nvml */
    rc = nvmlDeviceGetPciInfo(g_nvml.device, &pci);
    if (rc != NVML_SUCCESS)
    {
        WARN("NVML failed to query device ID: error %u\n", rc);
    }
    else
    {
    *pDeviceId = pci.pciDeviceId; 				/* Device and vendor ID 		*/
    *pSubSystemId = pci.pciSubSystemId;				/* Subsystem ID (board manufacturer) 	*/
    *pRevisionId = 161;						/* Rev A1 				*/
    TRACE("Device ID: %u, SubSysID: %u\n", pci.pciDeviceId, pci.pciSubSystemId);
    }
    return NVAPI_OK;
}

/* Get fan speed */
static NvAPI_Status CDECL NvAPI_GPU_GetTachReading(NvPhysicalGpuHandle hPhysicalGPU, NvU32 *pValue)
{
    nvmlReturn_t rc = NVML_SUCCESS;
    unsigned int speed, fan = 0;
    TRACE("(%p, %p)\n", hPhysicalGPU,  pValue);

    if (hPhysicalGPU != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGPU);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    rc = nvmlDeviceGetFanSpeed_v2(g_nvml.device, fan, &speed);
    if (rc != NVML_SUCCESS)
    {
        WARN("NVML failed to query fan speed: error %u\n", rc);
    }
    else
    {
    /* The value above is in % fan speed. Assuming average fan RPM is 3000 rpm we calculate */
    /* This value depends on manufacturer, but can be checked with Linux nVidia control panel */
    /* Rough estimate, and not truly importan if its +/- 200 rpm */
    *pValue = (speed * 30);		/* Result is 30 x % - eg: 100% = 3000 */
    TRACE("Fan speed is: %u percent\n", speed);
    }
    if (!pValue)
      return NVAPI_NOT_SUPPORTED;

    return NVAPI_OK;
}

/* Thermal Settings - GPU Temp */
static NvAPI_Status CDECL NvAPI_GPU_GetThermalSettings(NvPhysicalGpuHandle hPhysicalGpu, NvU32 sensorIndex, NV_GPU_THERMAL_SETTINGS *pThermalSettings)
{
    nvmlReturn_t rc = NVML_SUCCESS;
    nvmlTemperatureSensors_t sensorType;
    nvmlTemperatureThresholds_t thresholdType;
    unsigned int temp = 0;
    TRACE("(%p, %p)\n", hPhysicalGpu,  pThermalSettings);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }

    sensorIndex = 0;
    pThermalSettings->count = 1;
    pThermalSettings->sensor[0].controller = 1; /* Gpu_Internal */
    pThermalSettings->sensor[0].target = 1;						/* GPU */
    pThermalSettings->sensor[0].defaultMinTemp = 0;

    thresholdType = NVML_TEMPERATURE_THRESHOLD_GPU_MAX;
    rc = nvmlDeviceGetTemperatureThreshold(g_nvml.device, thresholdType, &temp);
    if (rc != NVML_SUCCESS)
    {
        WARN("NVML failed to query gpu max temp: error %u\n", rc);
    }
    else
    {
    pThermalSettings->sensor[0].defaultMaxTemp = temp;			/* GPU max temp threshold */
    TRACE("GPU Max temp: %u\n", temp);
    }

    sensorType = NVML_TEMPERATURE_GPU;
    rc = nvmlDeviceGetTemperature(g_nvml.device, sensorType, &temp);
    if (rc != NVML_SUCCESS)
    {
        WARN("NVML failed to query gpu temp: error %u\n", rc);
    }
    else
    {
    pThermalSettings->sensor[0].currentTemp = temp;	 		/* Current GPU Temp */
    TRACE("GPU temp: %u\n", temp);
    }
    return NVAPI_OK;
}

/* NvAPI Version String */
static NvAPI_Status CDECL NvAPI_GetInterfaceVersionString(NvAPI_ShortString szDesc)
{
    nvmlReturn_t rc = NVML_SUCCESS;
    char version[16];
    TRACE("(%p)\n", szDesc);
    /* Windows reports nvapi.dll version same as driver version */
    /* So i guess "shortversion" is as good as any number?      */
    rc = nvmlSystemGetDriverVersion(version, 16);               /* Get driver version */
    if (rc != NVML_SUCCESS) {
        WARN("invalid driver version!\n");
        return NVAPI_INVALID_POINTER;
    }
    else
    {
    strcpy(&version[3], &version[3 + 1]);			/* Truncate version     */
    strcpy(szDesc, version);
    }
    return NVAPI_OK;
}

/* nVidia GPU Bus Type */
static NvAPI_Status CDECL NvAPI_GPU_GetBusType(NvPhysicalGpuHandle hPhysicalGpu, NV_GPU_BUS_TYPE *pBusType)
{
    int btype;
    TRACE("(%p, %p)\n", hPhysicalGpu,  pBusType);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    /* Get GPU_BUS_TYPE from NVCtrl */
    open_disp();
    Bool bustype=XNVCTRLQueryAttribute(display, 0, 0, NV_CTRL_BUS_TYPE, &btype);
    close_disp();
    if (!bustype) {
            FIXME("invalid display: %d\n", btype);
            return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    /* NVCtrl has different type enum than nvapi, so some "conversion" must happen 	*/
    /* NVCTRL				NVAPI						*/
    /* AGP=0				0=undefined					*/
    /* PCI=1				1=PCI		(The same!)			*/
    /* PCIe=2				2=AGP						*/
    /* Integrated=3			3=PCIe						*/
    switch(btype){
       case 0: (*pBusType=2); break;
       case 1: (*pBusType=1); break;
       case 2: (*pBusType=3); break;
       case 3: (*pBusType=0); break;
       default: (*pBusType=0); break;
    }
    if (!pBusType)
      return NVAPI_INVALID_ARGUMENT;

    return NVAPI_OK;
}

/* nVidia GPU BusID */
static NvAPI_Status CDECL NvAPI_GPU_GetBusId(NvPhysicalGpuHandle hPhysicalGpu, NvU32 *pBusId)
{
    nvmlReturn_t rc = NVML_SUCCESS;
    nvmlPciInfo_t pci;
    TRACE("(%p, %p)\n", hPhysicalGpu,  pBusId);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }

    /* Get PCI_BUS_ID from nvml */
    rc = nvmlDeviceGetPciInfo(g_nvml.device, &pci);
    if (rc != NVML_SUCCESS)
    {
        WARN("NVML failed to query device ID: error %u\n", rc);
    }
    else
    {
    *pBusId = pci.bus;
    TRACE("PCI Bus ID: %d\n", pci.bus);
    }
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
    open_disp();
    Bool pipecores=XNVCTRLQueryAttribute(display,0,0, NV_CTRL_GPU_CORES, &numpipes);
    close_disp();
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
    open_disp();
    Bool shaderunits=XNVCTRLQueryAttribute(display,0,0, NV_CTRL_GPU_CORES, &numunits);
    close_disp();
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

/* Another Memory return function */
static NvAPI_Status CDECL NvAPI_GPU_GetMemoryInfo(NvPhysicalGpuHandle hPhysicalGpu, NV_DISPLAY_DRIVER_MEMORY_INFO *pMemoryInfo)
{
    TRACE("(%p, %p)\n", hPhysicalGpu, pMemoryInfo);

    if (!hPhysicalGpu)
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;

    pMemoryInfo->version = NV_DISPLAY_DRIVER_MEMORY_INFO_V3_VER;
    pMemoryInfo->dedicatedVideoMemory = get_video_memory_total();		/* Report total vram as dedicated vram */
    pMemoryInfo->availableDedicatedVideoMemory = get_video_memory_total();	/* Get available dedicated vram */
    pMemoryInfo->sharedSystemMemory = get_video_memory_total();			/* Caclulate possible virtual vram */
    pMemoryInfo->curAvailableDedicatedVideoMemory = get_video_memory_free();	/* Calculate available vram */

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

    *pRamType = 8;				/* No similar function in NVCtrl, so "type = 8" is GDDR5 */
    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_GPU_GetRamMaker(NvPhysicalGpuHandle hPhysicalGpu, NvU32 *pRamMaker)
{
    TRACE("(%p, %p)\n", hPhysicalGpu, pRamMaker);

    if (!hPhysicalGpu)
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;

    *pRamMaker = 0;                              /* Undocumented function. NVCtrl cannot get brand/maker. 0 = "unknown" */
    return NVAPI_OK;
}



/* Implement CoolerSettings */
static NvAPI_Status CDECL NvAPI_GPU_GetCoolerSettings(NvPhysicalGpuHandle hPhysicalGpu, NvU32 coolerIndex, NV_GPU_COOLER_SETTINGS *pCoolerInfo)
{
    int fanlevel, controltype;
    TRACE("(%p, %d, %p)\n", hPhysicalGpu, coolerIndex, pCoolerInfo);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    open_disp();
    Bool fanstatus=XNVCTRLQueryTargetAttribute(display,
                          NV_CTRL_TARGET_TYPE_COOLER,
                          0, // target_id
                          0, // display_mask
                          NV_CTRL_THERMAL_COOLER_CURRENT_LEVEL,
                          &fanlevel);				/* Reads cooler load in % */
    Bool type=XNVCTRLQueryTargetAttribute(display,
                          NV_CTRL_TARGET_TYPE_COOLER,
                          0, // target_id
                          0, // display_mask
                          NV_CTRL_THERMAL_COOLER_CONTROL_TYPE,
                          &controltype);
    close_disp();
    if (!fanstatus) {
        FIXME("invalid result: %d\n", fanlevel);
        return NVAPI_NOT_SUPPORTED;
    }
    if (!type) {
        FIXME("invalid result: %d\n", controltype);
        return NVAPI_NOT_SUPPORTED;
    }

    pCoolerInfo->version = NV_GPU_COOLER_SETTINGS_VER;
    pCoolerInfo->count = 1;
    pCoolerInfo->cooler[0].type = 1;				/* "Fan" type cooler */
    pCoolerInfo->cooler[0].controller = 2;			/* "Internal" controller */
    pCoolerInfo->cooler[0].defaultMinLevel = 0;
    pCoolerInfo->cooler[0].defaultMaxLevel = 100;
    pCoolerInfo->cooler[0].currentMinLevel = 0;
    pCoolerInfo->cooler[0].currentMaxLevel = 100;
    pCoolerInfo->cooler[0].currentLevel = fanlevel;		/* Fan level in % from NVCtrl */
    pCoolerInfo->cooler[0].defaultPolicy = 0;
    pCoolerInfo->cooler[0].currentPolicy = 0;
    pCoolerInfo->cooler[0].target = 1;				/* GPU */
    pCoolerInfo->cooler[0].controlType = controltype;		/* Cooler Control type from NVCtrl */
    pCoolerInfo->cooler[0].active = 1;
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

static NvAPI_Status CDECL NvAPI_GPU_ClientPowerTopologyGetStatus(void)
{
    TRACE("()\n");
    return NVAPI_NOT_SUPPORTED;
}

static NvAPI_Status CDECL NvAPI_GPU_ClientPowerPoliciesGetStatus(void)
{
    TRACE("()\n");
    return NVAPI_NOT_SUPPORTED;
}

static NvAPI_Status CDECL NvAPI_GPU_ClientPowerPoliciesGetInfo(void)
{
    TRACE("()\n");
    return NVAPI_NOT_SUPPORTED;
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
        return NVAPI_INVALID_HANDLE;
    }

    if (!pSize)
        return NVAPI_INVALID_ARGUMENT;

    *pSize = get_video_memory_total();
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
        return NVAPI_INVALID_HANDLE;
    }

    if (!pSize)
        return NVAPI_INVALID_ARGUMENT;

    *pSize = get_video_memory_total();
    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_GPU_GetGpuCoreCount(NvPhysicalGpuHandle hPhysicalGpu, NvU32 *pCount)
{
    int retcode = 0;
    int nCores = 0;
    TRACE("(%p, %p)\n", hPhysicalGpu, pCount);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }

    if (!pCount)
        return NVAPI_INVALID_ARGUMENT;

    retcode = nvidia_settings_query_attribute_int("[gpu:0]/CUDACores", &nCores);
    if (retcode != 0)
    {
        ERR("nvidia-settings query failed: %d\n", retcode);
        return NVAPI_ERROR;
    }

    *pCount = nCores;

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
        {0x33c7358c, NULL}, /* NvAPI_Diag_ReportCallStart, not needed */
        {0x593e8644, NULL}, /* NvAPI_Diag_ReportCallReturn, not needed */
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
	{0xda141340, NvAPI_GPU_GetCoolerSettings},
	{0xedcf624e, NvAPI_GPU_ClientPowerTopologyGetStatus},
	{0x70916171, NvAPI_GPU_ClientPowerPoliciesGetStatus},
	{0x34206d86, NvAPI_GPU_ClientPowerPoliciesGetInfo},
	{0x42aea16a, NvAPI_GPU_GetRamMaker},
	{0xba94c56e, NvAPI_GPU_GetPstatesInfo},
	{0x65b1c5f5, NvAPI_GPU_QueryActiveApps},
        {0x1bb18724, NvAPI_GPU_GetBusType},
	{0xd048c3b1, NvAPI_GPU_GetCurrentPCIEDownstreamWidth},
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

BOOL nvapi_init_nvml(void)
{
    nvmlReturn_t rc = nvmlInit();
    if (rc != NVML_SUCCESS)
    {
        ERR("Could not init NVML: error %u\n", rc);
        return FALSE;
    }

    rc = nvmlDeviceGetCount(&g_nvml.device_count);
    if (rc != NVML_SUCCESS)
    {
        ERR("Could not init get device count from NVML: error %u\n", rc);
        return FALSE;
    }

    if (g_nvml.device_count == 0)
    {
        ERR("NVML returned zero devices\n");
        return FALSE;
    }
    else if (g_nvml.device_count > 1) {
        WARN("NVML returned more than one device (%u), selecting the first one\n",
             g_nvml.device_count);
    }

    rc = nvmlDeviceGetHandleByIndex(0, &g_nvml.device);
    if (rc != NVML_SUCCESS)
    {
        ERR("Could not get NVML device handle: error %u\n", rc);
        return FALSE;
    }

    return TRUE;
}

BOOL nvapi_shutdown_nvml(void)
{
    nvmlReturn_t rc = nvmlShutdown();
    if (nvmlShutdown() != NVML_SUCCESS)
    {
        ERR("NVML shutdown failed: error %u\n", rc);
        return FALSE;
    }

    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    TRACE("(%p, %u, %p)\n", instance, reason, reserved);
    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(instance);

            if (!nvapi_init_nvml())
                ERR("Could not load NVML; failing out of DllMain\n");

            init_thunks();
            break;
        case DLL_PROCESS_DETACH:
            free_thunks();
            nvapi_shutdown_nvml();
            break;
    }

    return TRUE;
}
