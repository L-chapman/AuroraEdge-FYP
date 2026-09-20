param(
    [string]$OutputZip = "",
    [switch]$AllowDirty
)

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if ([string]::IsNullOrWhiteSpace($OutputZip)) {
    $OutputZip = Join-Path $ProjectRoot "dist\NorthFlux_Security.zip"
}

$OutputZip = [System.IO.Path]::GetFullPath($OutputZip)
$DistDir = Split-Path -Parent $OutputZip
$PackageRoot = "NorthFlux_Security"

$ExcludedFolderNames = @(
    ".git",
    ".git (1)",
    ".venv",
    ".pytest_cache",
    ".vscode",
    "__pycache__",
    "dist",
    "logs",
    "node_modules",
    "reports",
    "state"
)

$ExcludedRelativePaths = @()

$ExcludedFileNames = @(
    "Thumbs.db",
    ".DS_Store"
)

$ExcludedExtensions = @(
    ".zip",
    ".key",
    ".pem",
    ".crt",
    ".pfx",
    ".p12",
    ".jks",
    ".keystore",
    ".kdbx"
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

    if (
        $leaf -eq ".env" -or
        ($leaf.StartsWith(".env.") -and $leaf -ne ".env.example") -or
        $leaf.EndsWith(".local.cmd")
    ) {
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

if (-not (Test-Path (Join-Path $ProjectRoot ".git")) -or -not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "A Git checkout and the git command are required to create a reproducible release ZIP."
}

$gitStatus = & git -C $ProjectRoot status --porcelain --untracked-files=all
if ($LASTEXITCODE -ne 0) {
    throw "Unable to inspect the Git working tree."
}
if ($gitStatus -and -not $AllowDirty) {
    throw "Refusing to package a dirty working tree. Commit or stash changes, or rerun with -AllowDirty after reviewing every untracked file."
}

$gitArguments = @("-C", $ProjectRoot, "ls-files", "--cached")
if ($AllowDirty) {
    $gitArguments += @("--others", "--exclude-standard")
}
$eligiblePaths = & git @gitArguments
if ($LASTEXITCODE -ne 0 -or -not $eligiblePaths) {
    throw "Git did not return any eligible release files."
}

$files = @(
    $eligiblePaths |
        ForEach-Object { Join-Path $ProjectRoot $_ } |
        Where-Object {
            (Test-Path -LiteralPath $_ -PathType Leaf) -and -not (Test-ExcludedPath $_)
        } |
        ForEach-Object { Get-Item -LiteralPath $_ }
)

if (-not $files -or $files.Count -eq 0) {
    throw "No release files remain after applying the safety exclusions."
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

Write-Host "Created clean NorthFlux release ZIP:" -ForegroundColor Green
Write-Host "  $OutputZip"
Write-Host ""
Write-Host "The ZIP follows Git-tracked project files; -AllowDirty explicitly includes reviewed, non-ignored untracked files." -ForegroundColor DarkGray
Write-Host ""
Write-Host "Excluded from the ZIP:" -ForegroundColor Cyan
Write-Host "  .venv, .git, .git (1), .pytest_cache, .vscode, __pycache__, dist, logs, reports, state, local environments, private-key files, nested zip files"
