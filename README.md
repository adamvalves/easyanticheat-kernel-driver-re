# EasyAntiCheat.sys Kernel Driver RE — Technical Breakdown

An in-depth reverse engineering analysis of the `EasyAntiCheat.sys` kernel driver (dumped from Rust build). This document provides a technical overview of kernel detection vectors, import obfuscation routines, stack frame verification pipelines, and hardware attestation mechanisms implemented by EAC.

> **Note**: All binary offsets and virtual memory references in this document are rebased to `0x180000000`.

---

## 1. Import Obfuscation — `DecryptImport`

EAC avoids standard Import Address Table (IAT) resolution for sensitive kernel APIs. Instead, the driver imports a single export from its user-mode counterpart (`EasyAntiCheat_EOS`):

- **Import Export**: `DecryptImport`

Each sensitive kernel API pointer is resolved dynamically at runtime and encrypted per callsite. Callsites utilize distinct bitwise operations, bit-rotations (e.g., ROR8 by `1`, `5`, `11`, `15`, `21`, `23`, `29`, `39`, `41`, `45`, `47`, `55`), and unique 64-bit XOR keys:

```c
// SeRegisterImageVerificationCallback
func = ROR8(DecryptImport(&SeRegisterImageVerificationCallback), 55) ^ 0x110D352D969C8DD1;

// RtlWalkFrameChain
func = ROR8(DecryptImport(&RtlWalkFrameChain), 21) ^ 0x84720A4F2CD7A4C1;

// RtlVirtualUnwind
func = ROR8(~DecryptImport(&RtlVirtualUnwind), 1) ^ 0x2DBC37BB37609566;

// ExAcquirePushLockExclusiveEx
func = ROR8(DecryptImport(&ExAcquirePushLockExclusiveEx), 45) ^ 0x1CAD0BF732512BF7;
```

Over **47 encrypted callsites** were identified across the binary, masking routine access to functions including:
- `SeRegisterImageVerificationCallback` / `SeUnregisterImageVerificationCallback`
- `RtlWalkFrameChain`, `RtlVirtualUnwind`, `RtlLookupFunctionEntry`
- `ExAcquirePushLockExclusiveEx`, `ExReleasePushLockExclusiveEx`
- `Tbsi_Context_Create`, `Tbsi_GetDeviceInfo`, `Tbsip_Context_Close`

---

## 2. Driver Initialization & Anti-Disassembly

`DriverEntry` located at `0x18012E054` uses opaque jump sequences (`jmp $+1`) and inline junk instruction bytes to disrupt linear sweep disassemblers (IDA Pro / Ghidra):

```assembly
18012E054  push rcx
18012E055  lea  rcx, loc_18012E05C
18012E05C  add  rcx, 139E787h
18012E063  mov  [rsp+10h], rcx
18012E068  pop  rcx
18012E069  jmp  short near ptr loc_18012E069+1 ; Disassembly desynchronization
18012E06B  db   64h, 24h, 8, 6Bh, 7Fh
```

---

## 3. Direct IAT Imports Catalog

While critical routines are hidden behind `DecryptImport`, non-obfuscated imports reveal key functional modules:

### Filesystem Minifilter (`FLTMGR.sys`)
- `FltRegisterFilter`, `FltReadFile`, `FltGetFileNameInformation`
- `FltGetRequestorProcess`, `FltGetDestinationFileNameInformation`
- Monitors system-wide filesystem I/O operations, tracking process file access, file creation, and rename requests.

### Code Integrity (`CI.dll`)
- `CiValidateFileObject`, `CiFreePolicyInfo`
- Validates executable file object signatures against kernel code integrity policies.

### Cryptographic Provider (`CNG.sys` / `BCrypt`)
- `BCryptCreateHash`, `BCryptHashData`, `BCryptFinishHash`
- `BCryptGenerateSymmetricKey`, `BCryptDecrypt`, `BCryptVerifySignature`
- Performs payload decryption, integrity verification, and signature validation.

### Hardware Attestation & TPM (`TBS.sys`)
- `Tbsi_Context_Create`, `Tbsi_GetDeviceInfo`, `Tbsip_Submit_Command`
- Establishes TPM 2.0 communication context to execute hardware-rooted integrity checks and verify Platform Configuration Registers (PCRs).

---

## 4. Kernel Stack Validation Mechanism

EAC employs a multi-stage stack auditing pipeline to identify manually mapped drivers and unbacked execution regions.

### 4.1 Probabilistic Frame Capture (`sub_1800A6928`)
Triggered during kernel callback execution. To balance system performance, frame capture operates on a ~1% random sampling rate using `RtlRandomEx`:

```c
if (RtlRandomEx(&seed) % 100 == 0) {
    PEPROCESS process = IoThreadToProcess(current_thread);
    RtlWalkFrameChain(frame_buffer, 8, 1); // 1 = Kernel Mode
    memcpy(tracking_struct + 0x28, frame_buffer, 64);
}
```

### 4.2 Stack Unwinding & Verification (`sub_1800D7870`)
Captured stack frames are audited against registered kernel module bounds (`g_driver_base` – `g_driver_end`):

```c
bool validate_stack(stack_data) {
    if (get_eprocess(KeGetCurrentThread()) != PsInitialSystemProcess)
        return false;

    while (true) {
        PRUNTIME_FUNCTION unwind_info = RtlLookupFunctionEntry(rip, &image_base, NULL);
        if (!unwind_info) break;

        RtlVirtualUnwind(UNW_FLAG_NHANDLER, image_base, rip, unwind_info, ...);

        if (!rip) return valid_frames >= 3;

        // Verify return address resides within legitimate driver module range
        if (rip < g_driver_base || rip >= g_driver_end)
            return false; // Invalid / Unmapped Execution Frame Flagged

        valid_frames++;
    }
}
```
Any execution address pointing to unbacked memory or unlisted driver regions triggers immediate detection flags. Stacks containing fewer than 3 valid frames are likewise rejected.

---

## 5. Driver Load Interception

EAC registers a kernel-level driver load callback using `SeRegisterImageVerificationCallback` (`sub_1800080B0`), interfacing directly with `CI.dll`. Every kernel module loaded into system memory is intercepted prior to entry point execution for hash calculation and policy verification.

---

## 6. TPM 2.0 Hardware Attestation (`sub_18003C3BC`)

```c
NTSTATUS init_tpm(tpm_context_t* context) {
    context->magic = 0xFBF2AFA3761E188A;
    context->version = 2; // TPM 2.0

    TBS_CONTEXT_PARAMS params = { .version = 2 };
    if (Tbsi_Context_Create(&params, &context->handle) != 0)
        return STATUS_UNSUCCESSFUL;

    TPM_DEVICE_INFO info;
    if (Tbsi_GetDeviceInfo(sizeof(info), &info) != 0 || (info.flags & ~2) != 0) {
        Tbsip_Context_Close(context->handle);
        return STATUS_UNSUCCESSFUL;
    }

    context->cmd_buffer = ExAllocatePoolWithTag(NonPagedPool, 4096, 'mptT');
    return STATUS_SUCCESS;
}
```
Direct communication with the TPM hardware chip allows EAC to perform endorsement key queries and PCR attestation, establishing hardware-rooted identification independent of OS-level configuration.

---

## 7. Additional Detection Vectors

| Vector | Internal Routine / API | Description |
| :--- | :--- | :--- |
| **NMI Callbacks** | `KeDeregisterNmiCallback` (`sub_1800597C4`) | Issues non-maskable interrupts to audit active instruction pointers across CPU cores. |
| **ETW Tracing** | `NtTraceControl` | Configures Event Tracing for Windows to detect system call and driver telemetry tampering. |
| **VBS / HVCI Check** | `VslGetSecurePciEnabled` | Detects Virtualization-Based Security state to adjust integrity checks under VBS environments. |
| **Kernel Debugger** | `KdEnteredDebugger` | Audits active kernel debugging flags. |
| **Physical Memory Access** | `MmMapIoSpaceEx`, `MmCopyMemory` | Direct physical memory mapping for SMBIOS verification, DMA controller auditing, and table inspection. |

---

## Summary of Priority Severity

- **Critical**: Kernel Stack Walking (`RtlWalkFrameChain` / `RtlVirtualUnwind`), Driver Load Interception (`SeRegisterImageVerificationCallback`), Minifilter File Access Monitoring (`FLTMGR.sys`).
- **High**: TPM 2.0 Hardware Attestation (`TBS.sys`), Loaded Module Auditing (`PsLoadedModuleList`), Code Integrity Policy Validation (`CiValidateFileObject`).
- **Medium**: Non-Maskable Interrupts (`KeDeregisterNmiCallback`), Anti-Debugging (`KdEnteredDebugger`), Event Tracing (`NtTraceControl`).

---

## License

Distributed under the MIT License. See `LICENSE` for details.
