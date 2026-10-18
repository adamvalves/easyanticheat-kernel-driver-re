# Anti-Cheat Kernel Subsystems & Detection Architecture

## Architectural Overview

`EasyAntiCheat.sys` operates as a high-integrity Ring 0 protection driver designed to detect in-memory tampering, kernel hooks, thread hijacking, and unverified kernel drivers.

```text
[ Driver Initialization (0x18012E054) ]
                   │
                   ▼
[ Disassembly Desynchronization Engine ] (Opaque jumps & dead code injection)
                   │
                   ▼
       ┌───────────┴───────────┐
       ▼                       ▼
[ DecryptImport Resolver ]    [ Callback Subsystem Registration ]
- 47 encrypted callsites      - Image Verification (SeRegisterImageVerificationCallback)
- Per-site ROR8 + XOR         - Minifilter I/O (FltRegisterFilter / FLTMGR)
       │                       - Process/Thread Notification Callbacks
       │
       ▼
[ Runtime Telemetry & Verification Pipelines ]
       │
       ├─► Stack Frame Verification (RtlWalkFrameChain & RtlVirtualUnwind)
       │     - Verifies return addresses point to valid disk-backed image sections
       │     - Traps synthetic call frames, ROP chains, and spoofed stacks
       │
       └─► Hardware Attestation Pipeline (TBS.sys integration)
             - Issues Tbsi_Context_Create & Tbsi_GetDeviceInfo
             - Queries physical TPM 2.0 identity certificates and PCR registers
```

## Import Decryption State Transformation

Each masked kernel API address $A_{target}$ is reconstructed dynamically at the callsite:

$$A_{target} = \text{ROR}_{64}(\text{DecryptImport}(Descriptor), R) \oplus K_{xor}$$

Where:
- $R \in \{1, 5, 11, 15, 21, 23, 29, 39, 41, 45, 47, 55\}$ is the callsite-specific right-rotation shift count.
- $K_{xor}$ is a unique 64-bit constant mask.
- Certain callsites apply a preceding bitwise negation ($\sim$).

## Stack Frame Verification Mechanics

To counter return address spoofing in usermode and kernel callers:
1. `RtlWalkFrameChain` extracts the execution backtrace buffer.
2. For each RIP in the call chain, `RtlLookupFunctionEntry` resolves the `.pdata` runtime function table entry.
3. `RtlVirtualUnwind` steps through the function prologue and epilogue descriptors.
4. If an address resides in non-backed executable memory (`PAGE_EXECUTE_READWRITE` pool or dynamic allocation without a valid `_LDR_DATA_TABLE_ENTRY`), the caller is flagged.
