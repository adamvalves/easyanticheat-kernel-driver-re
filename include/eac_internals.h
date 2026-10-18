#ifndef EAC_INTERNALS_H
#define EAC_INTERNALS_H

#include <stdint.h>
#include <stdbool.h>

#define EAC_BASE_ADDRESS 0x180000000ULL

typedef uint64_t (*pfn_DecryptImport)(void* pImportDescriptor);

typedef struct _EAC_IMPORT_DESCRIPTOR {
    uint32_t RvaToHash;
    uint32_t RotationBits;
    uint64_t XorKey;
    bool     BitwiseInvert;
} EAC_IMPORT_DESCRIPTOR, *PEAC_IMPORT_DESCRIPTOR;

typedef struct _EAC_STACK_WALK_CONTEXT {
    uint32_t MaxFrames;
    uint32_t FramesWalked;
    void*    BackTrace[64];
    uint64_t HashResult;
} EAC_STACK_WALK_CONTEXT, *PEAC_STACK_WALK_CONTEXT;

typedef struct _EAC_TPM_CONTEXT {
    void*    TbsContext;
    uint32_t DeviceFlags;
    uint32_t TpmVersion;
    uint8_t  PublicIdBuffer[256];
    uint32_t PublicIdLength;
} EAC_TPM_CONTEXT, *PEAC_TPM_CONTEXT;

typedef struct _EAC_DISPATCH_TABLE {
    void* SeRegisterImageVerificationCallback;
    void* SeUnregisterImageVerificationCallback;
    void* RtlWalkFrameChain;
    void* RtlVirtualUnwind;
    void* RtlLookupFunctionEntry;
    void* ExAcquirePushLockExclusiveEx;
    void* ExReleasePushLockExclusiveEx;
    void* Tbsi_Context_Create;
    void* Tbsi_GetDeviceInfo;
    void* Tbsip_Context_Close;
} EAC_DISPATCH_TABLE, *PEAC_DISPATCH_TABLE;

#endif /* EAC_INTERNALS_H */
