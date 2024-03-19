/*
 * Copyright (C) 2015 Sebastian Lackner
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

#ifndef __WINE_CUDA_H
#define __WINE_CUDA_H

#include <stdint.h>
typedef uint32_t cuuint32_t;
typedef uint64_t cuuint64_t;

#ifdef _WIN32
#define CUDA_CB __stdcall
#else
#define CUDA_CB
#endif

#define CUDA_SUCCESS                 0
#define CUDA_ERROR_INVALID_VALUE     1
#define CUDA_ERROR_OUT_OF_MEMORY     2
#define CUDA_ERROR_INVALID_CONTEXT   201
#define CUDA_ERROR_NO_BINARY_FOR_GPU 209
#define CUDA_ERROR_FILE_NOT_FOUND    301
#define CUDA_ERROR_INVALID_HANDLE    400
#define CUDA_ERROR_NOT_SUPPORTED     801
#define CUDA_ERROR_UNKNOWN           999

#define CU_IPC_HANDLE_SIZE           64

#if defined(__x86_64) || defined(AMD64) || defined(_M_AMD64) || defined(__aarch64__)
typedef unsigned long long CUdeviceptr_v2;
#else
typedef unsigned int CUdeviceptr_v2;
#endif
typedef CUdeviceptr_v2 CUdeviceptr;

typedef enum CUdriverProcAddressQueryResult_enum {
    CU_GET_PROC_ADDRESS_SUCCESS                = 0,
    CU_GET_PROC_ADDRESS_SYMBOL_NOT_FOUND       = 1,
    CU_GET_PROC_ADDRESS_VERSION_NOT_SUFFICIENT = 2
}  CUdriverProcAddressQueryResult;

typedef unsigned long long CUmemGenericAllocationHandle_v1;
typedef CUmemGenericAllocationHandle_v1 CUmemGenericAllocationHandle;
typedef int CUGLDeviceList;
typedef int CUaddress_mode;
typedef int CUarray_format;
typedef int CUdevice_v1;
typedef CUdevice_v1 CUdevice;
typedef int CUdevice_attribute;
typedef int CUfilter_mode;
typedef int CUfunc_cache;
typedef int CUfunction_attribute;
typedef int CUipcMem_flags;
typedef int CUjitInputType;
typedef int CUjit_option;
typedef int CUlimit;
typedef int CUmemorytype;
typedef int CUpointer_attribute;
typedef int CUresourceViewFormat;
typedef int CUresourcetype;
typedef int CUresult;
typedef int CUsharedconfig;
typedef int CUstreamCaptureStatus;
typedef int CUstreamCaptureMode;
typedef int CUgraphMem_attribute;
typedef int CUmemPool_attribute;
typedef int CUmemAllocationGranularity_flags;
typedef int CUmemRangeHandleType;

typedef void *CUDA_ARRAY3D_DESCRIPTOR;
typedef void *CUDA_ARRAY_DESCRIPTOR;
typedef void *CUDA_MEMCPY2D;
typedef void *CUDA_MEMCPY3D;
typedef void *CUDA_MEMCPY3D_PEER;
typedef void *CUDA_RESOURCE_DESC;
typedef void *CUDA_RESOURCE_VIEW_DESC;
typedef void *CUDA_TEXTURE_DESC;
typedef void *CUDA_NODE_PARAMS;
typedef void *CUarray;
typedef void *CUcontext;
typedef void *CUdevprop;
typedef void *CUevent;
typedef void *CUfunction;
typedef void *CUgraphicsResource;
typedef void *CUlinkState;
typedef void *CUmipmappedArray;
typedef void *CUmodule;
typedef void *CUstream;
typedef void *CUsurfref;
typedef void *CUtexref;
typedef void *CUgraph;
typedef void *CUgraphExec;
typedef void *CUgraphNode;
typedef void *CUmemoryPool;
typedef void *CUmemAllocationProp;
typedef void *CUmoduleLoadingMode;
typedef void (CUDA_CB *CUhostFn)(void *userData);
typedef void *CUlaunchConfig;

typedef unsigned long long CUsurfObject;
typedef unsigned long long CUtexObject;

typedef struct CUipcEventHandle_st
{
    char reserved[CU_IPC_HANDLE_SIZE];
} CUipcEventHandle;

typedef struct CUipcMemHandle_st
{
    char reserved[CU_IPC_HANDLE_SIZE];
} CUipcMemHandle;

typedef struct CUuuid_st
{
    char bytes[16];
} CUuuid;

#endif /* __WINE_CUDA_H */
