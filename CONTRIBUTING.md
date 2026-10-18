# Contributing Guidelines

Contributions must maintain rigorous reverse engineering accuracy and low-level fidelity.

## Technical Standards

1. **Base Rebase Requirement**:
   - All addresses and offsets in documentation and scripts must strictly use the standard image base `0x180000000`.
2. **Mathematical Verification**:
   - Every XOR key and bitwise rotation (ROR8 / ROL8) must be mathematically verified against x86_64 disassembly instructions.
3. **Attribution & Persona**:
   - Zero emojis across all commits, PRs, comments, and documentation.
   - Authoritative, formal technical English.
