#requires -Version 7.0

param(
    [string]$OutputZip = "",
    [switch]$AllowDirty
)

$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if ([string]::IsNullOrWhiteSpace($OutputZip)) {
    $OutputZip = Join-Path $ProjectRoot "dist\NorthFlux_Security.zip"
}

$OutputZip = [System.IO.Path]::GetFullPath($OutputZip)
if ([System.IO.Path]::GetExtension($OutputZip) -ne ".zip") {
    throw "The output path must name a .zip file."
}
$ChecksumPath = "$OutputZip.sha256"
$DistDir = Split-Path -Parent $OutputZip
$PackageRoot = "NorthFlux_Security"

$ExcludedFolderNames = @(
    ".cache",
    ".aws",
    ".azure",
    ".e2e-data",
    ".git",
    ".git (1)",
    ".mypy_cache",
    ".nyc_output",
    ".secrets",
    ".ssh",
    ".venv",
    ".vite",
    ".pytest_cache",
    ".vscode",
    "__pycache__",
    "blob-report",
    "coverage",
    "dist",
    "htmlcov",
    "logs",
    "node_modules",
    "playwright-report",
    "reports",
    "state",
    "test-results"
)

$ExcludedRelativePaths = @()

$ExcludedFileNames = @(
    ".coverage",
    ".DS_Store",
    ".eslintcache",
    ".npmrc",
    ".pypirc",
    "coverage.xml",
    "credentials",
    "credentials.json",
    "id_dsa",
    "id_ed25519",
    "id_ecdsa",
    "id_rsa",
    "junit.xml",
    "Thumbs.db"
)

$ExcludedExtensions = @(
    ".zip",
    ".key",
    ".pem",
    ".crt",
    ".pfx",
    ".p12",
    ".der",
    ".jks",
    ".keystore",
    ".kdbx",
    ".p7b",
    ".p7c",
    ".tsbuildinfo"
)

function Get-RelativePathSafe {
    param([string]$TargetPath)

    $root = [System.IO.Path]::GetFullPath($ProjectRoot)
    $target = [System.IO.Path]::GetFullPath($TargetPath)
    $relative = [System.IO.Path]::GetRelativePath($root, $target)

    if (
        $relative -eq "." -or
        (
            $relative -ne ".." -and
            -not $relative.StartsWith(".." + [System.IO.Path]::DirectorySeparatorChar) -and
            -not [System.IO.Path]::IsPathRooted($relative)
        )
    ) {
        return $relative
    }

    throw "Release input is outside the project: $target"
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
        $leaf.EndsWith(".local.cmd") -or
        ($leaf.StartsWith("service-account", [System.StringComparison]::OrdinalIgnoreCase) -and
            [System.IO.Path]::GetExtension($leaf) -eq ".json")
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
        ForEach-Object { Get-Item -LiteralPath $_ -Force }
)

if (-not $files -or $files.Count -eq 0) {
    throw "No release files remain after applying the safety exclusions."
}

# Validate the checkout before touching the last good release. Build beside it,
# then replace the output only once the new archive and checksum are complete.
New-Item -ItemType Directory -Path $DistDir -Force | Out-Null
$TemporaryZip = Join-Path $DistDir (".northflux-" + [guid]::NewGuid().ToString("N") + ".zip")
$TemporaryChecksum = "$TemporaryZip.sha256"
$zip = [System.IO.Compression.ZipFile]::Open($TemporaryZip, [System.IO.Compression.ZipArchiveMode]::Create)
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

$archiveHash = (Get-FileHash -LiteralPath $TemporaryZip -Algorithm SHA256).Hash.ToLowerInvariant()
$checksumLine = "$archiveHash  $(Split-Path -Leaf $OutputZip)`n"
[System.IO.File]::WriteAllText(
    $TemporaryChecksum,
    $checksumLine,
    [System.Text.UTF8Encoding]::new($false)
)
Move-Item -LiteralPath $TemporaryZip -Destination $OutputZip -Force
Move-Item -LiteralPath $TemporaryChecksum -Destination $ChecksumPath -Force

Write-Host "Created clean NorthFlux release ZIP:" -ForegroundColor Green
Write-Host "  $OutputZip"
Write-Host "  $ChecksumPath"
Write-Host ""
Write-Host "The ZIP follows Git-tracked project files; -AllowDirty explicitly includes reviewed, non-ignored untracked files." -ForegroundColor DarkGray
Write-Host ""
Write-Host "Excluded from the ZIP:" -ForegroundColor Cyan
Write-Host "  VCS/virtual environments, runtime data, Node dependencies, build and test output, local environments, credential files, private-key material, and nested archives"
