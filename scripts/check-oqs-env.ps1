param()

$ErrorActionPreference = "Continue"

Write-Host "== RSRP OQS Environment Check (Windows) =="

function Test-Command($name) {
  $cmd = Get-Command $name -ErrorAction SilentlyContinue
  if ($null -eq $cmd) {
    Write-Host "[FAIL] Command not found: $name"
    return $false
  }
  Write-Host "[OK]   Command found: $name -> $($cmd.Source)"
  return $true
}

Test-Command "cargo" | Out-Null
Test-Command "cmake" | Out-Null
Test-Command "clang" | Out-Null

if ([string]::IsNullOrWhiteSpace($env:LIBCLANG_PATH)) {
  Write-Host "[FAIL] LIBCLANG_PATH is not set"
} else {
  Write-Host "[OK]   LIBCLANG_PATH=$env:LIBCLANG_PATH"
  $dll1 = Join-Path $env:LIBCLANG_PATH "libclang.dll"
  $dll2 = Join-Path $env:LIBCLANG_PATH "clang.dll"
  if ((Test-Path $dll1) -or (Test-Path $dll2)) {
    Write-Host "[OK]   libclang DLL found in LIBCLANG_PATH"
  } else {
    Write-Host "[FAIL] No libclang.dll/clang.dll found in LIBCLANG_PATH"
  }
}

$llvmDefault = "C:\Program Files\LLVM\bin"
if (Test-Path $llvmDefault) {
  Write-Host "[INFO] LLVM default path exists: $llvmDefault"
  if (Test-Path (Join-Path $llvmDefault "libclang.dll")) {
    Write-Host "[INFO] libclang.dll detected at default LLVM path"
  }
}

Write-Host ""
Write-Host "Try build check:"
Write-Host "cargo check -p rsrp-pqcrypto --release --no-default-features --features real-crypto"
