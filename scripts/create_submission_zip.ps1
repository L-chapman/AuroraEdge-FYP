param(
    [string]$OutputZip = ""
)

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if ([string]::IsNullOrWhiteSpace($OutputZip)) {
    $OutputZip = Join-Path $ProjectRoot "dist\AuroraEdge_FYP_submission.zip"
}

$OutputZip = [System.IO.Path]::GetFullPath($OutputZip)
$DistDir = Split-Path -Parent $OutputZip
$StagingDir = Join-Path $DistDir "AuroraEdge_FYP_submission"

$ExcludedFolderNames = @(
    ".git",
    ".git (1)",
    ".venv",
    ".pytest_cache",
    ".vscode",
    "__pycache__",
    "dist",
    "logs",
    "node_modules"
)

$ExcludedRelativePaths = @(
    "reports\archive",
    "state\auroraedge.db",
    "state\auroraedge.db-shm",
    "state\auroraedge.db-wal"
)

$ExcludedFileNames = @(
    "Thumbs.db",
    ".DS_Store"
)

function Get-RelativePathSafe {
    param([string]$TargetPath)

    $root = [System.IO.Path]::GetFullPath($ProjectRoot)
    $target = [System.IO.Path]::GetFullPath($TargetPath)

    if ($target.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $target.Substring($root.Length).TrimStart("\\")
    }

    return Split-Path -Leaf $target
}

function Test-ExcludedPath {
    param([string]$FullPath)

    $relativePath = Get-RelativePathSafe -TargetPath $FullPath
    if ($relativePath -eq ".") {
        return $true
    }

    foreach ($part in ($relativePath -split "[\\/]")) {
        if ($ExcludedFolderNames -contains $part) {
            return $true
        }
    }

    foreach ($excluded in $ExcludedRelativePaths) {
        if ($relativePath -eq $excluded -or $relativePath.StartsWith($excluded + "\")) {
            return $true
        }
    }

    $leaf = Split-Path -Leaf $FullPath
    if ($ExcludedFileNames -contains $leaf) {
        return $true
    }

    if ($leaf.EndsWith(".pyc") -or $leaf.EndsWith(".pyo")) {
        return $true
    }

    return $false
}

if (Test-Path $StagingDir) {
    Remove-Item -LiteralPath $StagingDir -Recurse -Force
}

New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null
New-Item -ItemType Directory -Path $DistDir -Force | Out-Null

$files = Get-ChildItem -LiteralPath $ProjectRoot -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object {
    -not (Test-ExcludedPath $_.FullName)
}

foreach ($file in $files) {
    $relativePath = Get-RelativePathSafe -TargetPath $file.FullName
    $destination = Join-Path $StagingDir $relativePath
    $destinationDir = Split-Path -Parent $destination

    if (-not (Test-Path $destinationDir)) {
        New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null
    }

    Copy-Item -LiteralPath $file.FullName -Destination $destination -Force
}

if (Test-Path $OutputZip) {
    Remove-Item -LiteralPath $OutputZip -Force
}

Compress-Archive -Path (Join-Path $StagingDir "*") -DestinationPath $OutputZip -Force
Remove-Item -LiteralPath $StagingDir -Recurse -Force

Write-Host "Created clean submission ZIP:" -ForegroundColor Green
Write-Host "  $OutputZip"
Write-Host ""
Write-Host "Excluded from the ZIP:" -ForegroundColor Cyan
Write-Host "  .venv, .git, .git (1), .pytest_cache, .vscode, __pycache__, logs, state DB files, reports/archive"