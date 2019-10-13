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

#include <stdarg.h>
#include <stdio.h>

#define COBJMACROS
#include "initguid.h"
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "wine/debug.h"
#include "wine/list.h"
#include "nvapi_lite.h"
#include "nvShaderExtnEnums.h"
#include "d3d9.h"
#include "d3d11.h"
#include "dxvk.h"

WINE_DEFAULT_DEBUG_CHANNEL(nvapi);

#define FAKE_PHYSICAL_GPU ((NvPhysicalGpuHandle)0xdead0001)
#define FAKE_DISPLAY ((NvDisplayHandle)0xdead0002)
#define FAKE_LOGICAL_GPU ((NvLogicalGpuHandle)0xdead0003)
#define FAKE_DISPLAY_ID ((NvU32)0xdead0004)

nvapi_nvml_state g_nvml;
#if defined(__i386__) || defined(__x86_64__)

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

static NvAPI_Status CDECL NvAPI_DISP_GetDisplayIdByDisplayName(NvDisplayHandle *pNvDispHandle, NvU32* displayId)
{
    TRACE("(%p, %p)\n", pNvDispHandle, displayId);

    if (!displayId)
        return NVAPI_INVALID_ARGUMENT;

    if (!pNvDispHandle)
        return NVAPI_INVALID_ARGUMENT;

    *displayId = FAKE_DISPLAY_ID;

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

/* Get device and vendor id from nvml to create NVAPI PCI ID's */
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
    *pRevisionId = 161;						/* Rev A1? 				*/
    TRACE("Device ID: %u, SubSysID: %u, RevisionID: %p\n", pci.pciDeviceId, pci.pciSubSystemId, pRevisionId);
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
        WARN("NVML failed to query BUSID: error %u\n", rc);
    }
    else
    {
    *pBusId = pci.bus;
    TRACE("PCI Bus ID: %p\n", pBusId);
    }
    if (!pBusId)
      return NVAPI_INVALID_ARGUMENT;

    return NVAPI_OK;
}

/* Shader Pipe Count (Se note below) */
static NvAPI_Status CDECL NvAPI_GPU_GetShaderPipeCount(NvPhysicalGpuHandle hPhysicalGpu, NvU32 *pShaderPipeCount)
{
    int retcode, nCores = 0;
    TRACE("(%p, %p)\n", hPhysicalGpu,  pShaderPipeCount);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    /* Read number of "cores" from nvidia-settings */
    retcode = nvidia_settings_query_attribute_int("[gpu:0]/CUDACores", &nCores);
    if (retcode != 0)
    {
        ERR("nvidia-settings query failed: %d\n", retcode);
        return NVAPI_ERROR;
    }

    *pShaderPipeCount = nCores;
    if (!pShaderPipeCount)
      return NVAPI_INVALID_ARGUMENT;

    return NVAPI_OK;
}

/* Uncertain of the difference between shader pipe and shader unit.
   "Shader Units" = GPU_CORES ?				*/
static NvAPI_Status CDECL NvAPI_GPU_GetShaderSubPipeCount(NvPhysicalGpuHandle hPhysicalGpu, NvU32 *pCount)
{
    int retcode, nCores = 0;
    TRACE("(%p, %p)\n", hPhysicalGpu,  pCount);

    if (hPhysicalGpu != FAKE_PHYSICAL_GPU)
    {
        FIXME("invalid handle: %p\n", hPhysicalGpu);
        return NVAPI_EXPECTED_PHYSICAL_GPU_HANDLE;
    }
    retcode = nvidia_settings_query_attribute_int("[gpu:0]/CUDACores", &nCores);
    if (retcode != 0)
    {
        ERR("nvidia-settings query failed: %d\n", retcode);
        return NVAPI_ERROR;
    }
    *pCount = nCores;
    if (!pCount)
      return NVAPI_INVALID_ARGUMENT;

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
    int retcode, nCores = 0;
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
    ID3D11Device *d3d11_device;
    ID3D11DeviceContext *ctx;
    ID3D11VkExtDevice *dxvk_ext_device;
    ID3D11VkExtContext *dxvk_ext_context;

    TRACE("(%p, %u, %f, %f): dxvk\n", pDeviceOrContext, bEnable, fMinDepth, fMaxDepth);

    if (!pDeviceOrContext)
        return NVAPI_INVALID_ARGUMENT;

    if (0 > fMinDepth || fMinDepth > fMaxDepth || fMaxDepth > 1)
    {
        ERR("(%p, %u, %f, %f): Invalid argument!\n", pDeviceOrContext, bEnable, fMinDepth, fMaxDepth);
        return NVAPI_OK; /* Hack: Don't crash games */
        /*return NVAPI_INVALID_ARGUMENT;*/
    }

    if (FAILED(IUnknown_QueryInterface(pDeviceOrContext, &IID_ID3D11VkExtDevice, (void **)&dxvk_ext_device)))
    {
        ERR("Failed to get DXVK extension device handle!\n");
        return NVAPI_ERROR;
    }

    if(!ID3D11VkExtDevice_GetExtensionSupport(dxvk_ext_device, D3D11_VK_EXT_DEPTH_BOUNDS))
    {
        ERR("DXVK extension not supported!\n");
        return NVAPI_ERROR;
    }

    if (FAILED(IUnknown_QueryInterface(pDeviceOrContext, &IID_ID3D11Device, (void **)&d3d11_device)))
    {
        ERR("Failed to get DXVK device handle!\n");
        return NVAPI_ERROR;
    }

    ID3D11Device_GetImmediateContext(d3d11_device, &ctx);
    if (FAILED(IUnknown_QueryInterface(ctx, &IID_ID3D11VkExtContext, (void **)&dxvk_ext_context)))
    {
        ERR("Failed to get DXVK context handle!\n");
        return NVAPI_ERROR;
    }

    ID3D11VkExtContext_SetDepthBoundsTest(dxvk_ext_context, bEnable, fMinDepth, fMaxDepth);

    return NVAPI_OK;
}

static NvAPI_Status CDECL NvAPI_D3D11_IsNvShaderExtnOpCodeSupported(IUnknown *pDeviceOrContext, NvU32 opCode, BOOL *pSupported)
{
    if (!pDeviceOrContext)
        return NVAPI_INVALID_ARGUMENT;

/* This requires some experimentation. This is HSLS shader extension support for the adapter */

    switch(opCode){
       case NV_EXTN_OP_SHFL: (*pSupported = TRUE); break;
       case NV_EXTN_OP_SHFL_UP: (*pSupported = TRUE); break;
       case NV_EXTN_OP_SHFL_DOWN: (*pSupported = TRUE); break;
       case NV_EXTN_OP_SHFL_XOR: (*pSupported = TRUE); break;
       case NV_EXTN_OP_VOTE_ALL: (*pSupported = TRUE); break;
       case NV_EXTN_OP_VOTE_ANY: (*pSupported = TRUE); break;
       case NV_EXTN_OP_VOTE_BALLOT: (*pSupported = TRUE); break;
       case NV_EXTN_OP_GET_LANE_ID: (*pSupported = TRUE); break;
       case NV_EXTN_OP_FP16_ATOMIC: (*pSupported = TRUE); break;
       case NV_EXTN_OP_FP32_ATOMIC: (*pSupported = TRUE); break;
       case NV_EXTN_OP_UINT64_ATOMIC: (*pSupported = TRUE); break;
       case NV_EXTN_OP_GET_SHADING_RATE: (*pSupported = TRUE); break;
       case NV_EXTN_OP_VPRS_EVAL_ATTRIB_AT_SAMPLE: (*pSupported = TRUE); break;
       case NV_EXTN_OP_VPRS_EVAL_ATTRIB_SNAPPED: (*pSupported = TRUE); break;
       default: (*pSupported = FALSE); break;
    }
    TRACE("(%p, %d, %p)\n", pDeviceOrContext, opCode, pSupported);

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
        {0x4b708b54, NvAPI_D3D_GetCurrentSLIState},
        {0xee1370cf, NvAPI_GetLogicalGPUFromDisplay},
        {0xfceac864, NvAPI_D3D_GetObjectHandleForResource},
        {0xa064bdfc, NvAPI_D3D9_RegisterResource},
        {0x46fbeb03, NvAPI_GPU_GetPhysicalFrameBufferSize},
        {0x5a04b644, NvAPI_GPU_GetVirtualFrameBufferSize},
        {0xc7026a87, NvAPI_GPU_GetGpuCoreCount},
	{0x1890e8da, NvAPI_GetPhysicalGPUFromDisplay},
	{0x7a4174f4, NvAPI_GPU_PhysxQueryRecommendedState},
	{0x35B5fd2f, NvAPI_GPU_GetTargetID},
	{0x2ddfb66e, NvAPI_GPU_GetPCIIdentifiers},
	{0x01053fa5, NvAPI_GetInterfaceVersionString},
	{0x1be0b8e5, NvAPI_GPU_GetBusId},
	{0x63e2f56f, NvAPI_GPU_GetShaderPipeCount},
	{0x0be17923, NvAPI_GPU_GetShaderSubPipeCount},
        {0x7aaf7a04, NvAPI_D3D11_SetDepthBoundsTest},
        {0x6a16d3a0, NvAPI_D3D11_CreateDevice},
        {0xbb939ee5, NvAPI_D3D11_CreateDeviceAndSwapChain},
	{0x07f9b368, NvAPI_GPU_GetMemoryInfo},
	{0xae457190, NvAPI_DISP_GetDisplayIdByDisplayName},
	{0x5f68da40, NvAPI_D3D11_IsNvShaderExtnOpCodeSupported},
        {0xd22bdd7e, NvAPI_Unload},
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
