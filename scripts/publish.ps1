[CmdletBinding()]
param(
    [string[]]$Packages = @(
        "rsrp-security-core",
        "rsrp-policy-dsl",
        "rsrp-immutable-ledger",
        "rsrp-pqcrypto",
        "rsrp-proof-engine"
    ),
    [switch]$DryRun,
    [switch]$AllowDirty,
    [int]$PublishRetries = 3,
    [int]$RetryDelaySeconds = 20,
    [int]$AvailabilityTimeoutSeconds = 180,
    [int]$AvailabilityPollSeconds = 5,
    [switch]$SkipAvailabilityWait,
    [switch]$RunWorkspaceChecks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info([string]$Message) {
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-WarnMsg([string]$Message) {
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-ErrMsg([string]$Message) {
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Get-RepoRoot {
    if (-not $PSScriptRoot) {
        throw "PSScriptRoot unavailable"
    }
    return (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

function Get-WorkspaceVersion([string]$RepoRoot) {
    $cargoToml = Join-Path $RepoRoot "Cargo.toml"
    if (-not (Test-Path $cargoToml)) {
        throw "Workspace Cargo.toml not found at $cargoToml"
    }

    $lines = Get-Content $cargoToml
    $inWorkspacePackage = $false
    foreach ($line in $lines) {
        if ($line -match '^\s*\[workspace\.package\]\s*$') {
            $inWorkspacePackage = $true
            continue
        }
        if ($inWorkspacePackage -and $line -match '^\s*\[') {
            break
        }
        if ($inWorkspacePackage -and $line -match '^\s*version\s*=\s*"([^"]+)"\s*$') {
            return $Matches[1]
        }
    }
    throw "workspace.package.version not found in $cargoToml"
}

function Test-CrateVersionAvailable([string]$CrateName, [string]$Version) {
    $url = "https://crates.io/api/v1/crates/$CrateName"
    try {
        $resp = Invoke-RestMethod -Method Get -Uri $url -TimeoutSec 15
    } catch {
        Write-WarnMsg "crates.io API check failed for ${CrateName}: $($_.Exception.Message)"
        return $false
    }

    if ($null -eq $resp -or $null -eq $resp.versions) {
        return $false
    }
    foreach ($v in $resp.versions) {
        if ($v.num -eq $Version) {
            return $true
        }
    }
    return $false
}

function Wait-CrateVersionAvailable(
    [string]$CrateName,
    [string]$Version,
    [int]$TimeoutSeconds,
    [int]$PollSeconds
) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-CrateVersionAvailable -CrateName $CrateName -Version $Version) {
            Write-Info "$CrateName $Version is visible on crates.io"
            return
        }
        Start-Sleep -Seconds $PollSeconds
    }
    throw "Timeout waiting for $CrateName $Version to appear on crates.io"
}

function Invoke-CargoCommand([string[]]$Args) {
    Write-Info ("cargo " + ($Args -join " "))
    & cargo @Args
    if ($LASTEXITCODE -ne 0) {
        throw "cargo command failed with exit code $LASTEXITCODE"
    }
}

function Publish-CrateWithRetry(
    [string]$CrateName,
    [switch]$DryRunMode,
    [switch]$AllowDirtyMode,
    [int]$Retries,
    [int]$DelaySeconds
) {
    $args = @("publish", "-p", $CrateName)
    if ($DryRunMode) {
        $args += "--dry-run"
    }
    if ($AllowDirtyMode) {
        $args += "--allow-dirty"
    }

    for ($attempt = 1; $attempt -le $Retries; $attempt++) {
        try {
            Invoke-CargoCommand -Args $args
            return
        } catch {
            if ($attempt -ge $Retries) {
                throw
            }
            Write-WarnMsg "Publish attempt $attempt/$Retries failed for ${CrateName}: $($_.Exception.Message)"
            Write-WarnMsg "Retrying in $DelaySeconds seconds..."
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

$repoRoot = Get-RepoRoot
$workspaceVersion = Get-WorkspaceVersion -RepoRoot $repoRoot

Write-Info "Repo root: $repoRoot"
Write-Info "Workspace version: $workspaceVersion"
Write-Info "Packages: $($Packages -join ', ')"
if ($DryRun) { Write-Info "Mode: dry-run" }
if ($AllowDirty) { Write-WarnMsg "Mode: allow-dirty enabled" }

Push-Location $repoRoot
try {
    if ($RunWorkspaceChecks) {
        Write-Info "Running workspace checks before publish"
        Invoke-CargoCommand -Args @("check", "--workspace")
        Invoke-CargoCommand -Args @("test", "--workspace")
    }

    foreach ($pkg in $Packages) {
        if (-not $DryRun -and (Test-CrateVersionAvailable -CrateName $pkg -Version $workspaceVersion)) {
            Write-WarnMsg "$pkg $workspaceVersion already exists on crates.io, skipping"
            continue
        }

        Publish-CrateWithRetry `
            -CrateName $pkg `
            -DryRunMode:$DryRun `
            -AllowDirtyMode:$AllowDirty `
            -Retries $PublishRetries `
            -DelaySeconds $RetryDelaySeconds

        if (-not $DryRun -and -not $SkipAvailabilityWait) {
            Wait-CrateVersionAvailable `
                -CrateName $pkg `
                -Version $workspaceVersion `
                -TimeoutSeconds $AvailabilityTimeoutSeconds `
                -PollSeconds $AvailabilityPollSeconds
        }
    }

    Write-Info "Publish workflow completed"
} finally {
    Pop-Location
}
