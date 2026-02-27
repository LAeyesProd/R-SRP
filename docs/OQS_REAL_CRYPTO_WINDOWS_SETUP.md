# OQS `real-crypto` Setup on Windows (RSRP / `rsrp-pqcrypto`)

Date: `2026-02-26`  
Target: `rsrp-pqcrypto --features real-crypto`

## Purpose

Enable the `real-crypto` feature of `rsrp-pqcrypto` using the `oqs` Rust crate (`liboqs` backend).

This is required for:

- release builds of `rsrp-pqcrypto`
- validating non-mock ML-DSA / ML-KEM paths

## Why Builds Fail by Default

Observed local failure (Windows):

- `oqs-sys` build fails because `bindgen` cannot find `libclang.dll`
- error message mentions:
  - `Unable to find libclang`
  - `set the LIBCLANG_PATH environment variable`

`oqs-sys` uses `bindgen`, which requires LLVM/Clang libraries available on the machine.

## Prerequisites

Install these components:

1. LLVM/Clang (must include `libclang.dll`)
2. Visual Studio Build Tools (C/C++ toolchain)
3. CMake
4. Git (usually already installed)

Recommended on Windows:

- `Visual Studio Build Tools 2022` with `Desktop development with C++`
- `LLVM` installer (official) with `Add LLVM to PATH` optional
- `CMake` (official installer or package manager)

## Required Environment Variables

Set `LIBCLANG_PATH` to the directory containing `libclang.dll`.

Typical paths:

- `C:\Program Files\LLVM\bin`
- `C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Tools\Llvm\x64\bin` (if present)

PowerShell (current session):

```powershell
$env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"
```

Persist for user profile:

```powershell
[Environment]::SetEnvironmentVariable(
  "LIBCLANG_PATH",
  "C:\Program Files\LLVM\bin",
  "User"
)
```

## Optional but Useful PATH Entries

Add to `PATH` if not already present:

- LLVM bin directory
- CMake binary directory
- Visual Studio Build Tools / Developer Command Prompt environment

## Validation Commands

Run from repo root:

```powershell
cargo check -p rsrp-pqcrypto --release --no-default-features --features real-crypto
```

Expected outcomes:

- `real-crypto` path compiles if toolchain is correctly installed
- if `liboqs`/toolchain is missing, error will point to native prerequisites

Dev (mock) path remains available:

```powershell
cargo test -p rsrp-pqcrypto --lib
```

## Troubleshooting

### Error: `Unable to find libclang`

Cause:

- LLVM not installed, or `LIBCLANG_PATH` not set to the directory containing `libclang.dll`

Fix:

- install LLVM
- set `LIBCLANG_PATH`
- restart terminal

### Error: `cmake` not recognized

Cause:

- CMake not installed or not in PATH

Fix:

- install CMake
- reopen terminal

### Error: MSVC / linker / compiler not found

Cause:

- Visual Studio Build Tools missing

Fix:

- install `Desktop development with C++`
- use `x64 Native Tools Command Prompt for VS`

### Error: OQS algorithm disabled

Cause:

- feature mismatch or OQS build config lacking algorithm family

Fix:

- ensure `oqs` features include `ml_dsa` and `ml_kem` (already configured in `rsrp-pqcrypto`)
- rebuild cleanly:

```powershell
cargo clean -p rsrp-pqcrypto
```

## RSRP Notes

- `rsrp-pqcrypto` enforces `real-crypto` for release builds
- mock backend is intended for development/tests only
- current `real-crypto` implementation targets:
  - ML-DSA (`oqs::sig::Algorithm::MlDsa44/65/87`)
  - ML-KEM (`oqs::kem::Algorithm::MlKem512/768/1024`)

## Quick Checklist

- [ ] LLVM installed
- [ ] `libclang.dll` present
- [ ] `LIBCLANG_PATH` set correctly
- [ ] CMake installed
- [ ] MSVC Build Tools installed
- [ ] `cargo check -p rsrp-pqcrypto --release --no-default-features --features real-crypto` passes
