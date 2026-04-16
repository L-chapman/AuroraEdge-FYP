param(
    [string]$OutputZip = ""
)

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if ([string]::IsNullOrWhiteSpace($OutputZip)) {
    $OutputZip = Join-Path $ProjectRoot "dist\AuroraEdge_FYP_submission.zip"
}

$OutputZip = [System.IO.Path]::GetFullPath($OutputZip)
$DistDir = Split-Path -Parent $OutputZip
$PackageRoot = "AuroraEdge_FYP_submission"

$ExcludedFolderNames = @(
    ".github",
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
    "state\auroraedge.db",
    "state\auroraedge.db-shm",
    "state\auroraedge.db-wal"
)

$ExcludedFileNames = @(
    "Thumbs.db",
    ".DS_Store"
)

$ExcludedExtensions = @(
    ".zip"
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

    if ($ExcludedExtensions -contains ([System.IO.Path]::GetExtension($leaf).ToLowerInvariant())) {
        return $true
    }

    if ($leaf.EndsWith(".pyc") -or $leaf.EndsWith(".pyo")) {
        return $true
    }

    return $false
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

if (Test-Path $OutputZip) {
    Remove-Item -LiteralPath $OutputZip -Force
}

New-Item -ItemType Directory -Path $DistDir -Force | Out-Null

$files = @()

if ((Test-Path (Join-Path $ProjectRoot ".git")) -and (Get-Command git -ErrorAction SilentlyContinue)) {
    $trackedPaths = & git -C $ProjectRoot ls-files
    if ($LASTEXITCODE -eq 0 -and $trackedPaths) {
        $files = @(
            $trackedPaths |
                ForEach-Object { Join-Path $ProjectRoot $_ } |
                Where-Object {
                    (Test-Path -LiteralPath $_ -PathType Leaf) -and -not (Test-ExcludedPath $_)
                } |
                ForEach-Object { Get-Item -LiteralPath $_ }
        )
    }
}

if (-not $files -or $files.Count -eq 0) {
    $files = @(Get-ChildItem -LiteralPath $ProjectRoot -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object {
        -not (Test-ExcludedPath $_.FullName)
    })
}

$zip = [System.IO.Compression.ZipFile]::Open($OutputZip, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($file in $files) {
        $relativePath = Get-RelativePathSafe -TargetPath $file.FullName
        $entryPath = ($PackageRoot + "/" + ($relativePath -replace "\\", "/")).TrimEnd("/")
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
            $zip,
            $file.FullName,
            $entryPath,
            [System.IO.Compression.CompressionLevel]::Optimal
        ) | Out-Null
    }
}
finally {
    $zip.Dispose()
}

Write-Host "Created clean submission ZIP:" -ForegroundColor Green
Write-Host "  $OutputZip"
Write-Host ""
Write-Host "The ZIP follows the tracked project files when run from a Git checkout." -ForegroundColor DarkGray
Write-Host ""
Write-Host "Excluded from the ZIP:" -ForegroundColor Cyan
Write-Host "  .github, .venv, .git, .git (1), .pytest_cache, .vscode, __pycache__, dist, logs, state DB files, nested zip files"