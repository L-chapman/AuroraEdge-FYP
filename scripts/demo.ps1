<#
.SYNOPSIS
    AuroraEdge Interactive Demo Script
    For easy testing by lecturers and evaluators

.DESCRIPTION
    This script provides a friendly menu-driven interface to test
    all features of the AuroraEdge Security cyber defence system.

.AUTHOR
    Leon Chapman (50030738)
    Belfast Met - Cybersecurity & Networking Infrastructure
    Final Year Project 2025/2026
#>

# Set console encoding and colors
$Host.UI.RawUI.WindowTitle = "AuroraEdge Demo"
$ErrorActionPreference = "Stop"

# Project paths
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$SrcDir = Join-Path $ProjectRoot "src"
$ReportsDir = Join-Path $ProjectRoot "reports"
$DomainsFile = Join-Path $ProjectRoot "domains.txt"

# Ensure PYTHONPATH is set
$env:PYTHONPATH = $SrcDir

function Write-Header {
    Clear-Host
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║                                                               ║" -ForegroundColor Cyan
    Write-Host "  ║   " -ForegroundColor Cyan -NoNewline
    Write-Host "🛡️  AuroraEdge Security" -ForegroundColor White -NoNewline
    Write-Host "                    ║" -ForegroundColor Cyan
    Write-Host "  ║                                                               ║" -ForegroundColor Cyan
    Write-Host "  ║   " -ForegroundColor Cyan -NoNewline
    Write-Host "Interactive Demo & Testing Interface" -ForegroundColor Gray -NoNewline
    Write-Host "                     ║" -ForegroundColor Cyan
    Write-Host "  ║   " -ForegroundColor Cyan -NoNewline
    Write-Host "Leon Chapman (50030738) - Belfast Met FYP" -ForegroundColor DarkGray -NoNewline
    Write-Host "                ║" -ForegroundColor Cyan
    Write-Host "  ║                                                               ║" -ForegroundColor Cyan
    Write-Host "  ╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Success {
    param([string]$Message)
    Write-Host "  ✓ " -ForegroundColor Green -NoNewline
    Write-Host $Message -ForegroundColor White
}

function Write-Info {
    param([string]$Message)
    Write-Host "  ℹ " -ForegroundColor Blue -NoNewline
    Write-Host $Message -ForegroundColor Gray
}

function Write-Warn {
    param([string]$Message)
    Write-Host "  ⚠ " -ForegroundColor Yellow -NoNewline
    Write-Host $Message -ForegroundColor White
}

function Write-Error {
    param([string]$Message)
    Write-Host "  ✗ " -ForegroundColor Red -NoNewline
    Write-Host $Message -ForegroundColor White
}

function Show-Menu {
    Write-Host ""
    Write-Host "  ┌───────────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "  │  " -ForegroundColor DarkGray -NoNewline
    Write-Host "CLI TESTING" -ForegroundColor Yellow -NoNewline
    Write-Host "                                                  │" -ForegroundColor DarkGray
    Write-Host "  ├───────────────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
    Write-Host "  │  " -ForegroundColor DarkGray -NoNewline
    Write-Host "[1]" -ForegroundColor Cyan -NoNewline
    Write-Host " Scan a Single Domain                                   │" -ForegroundColor White
    Write-Host "  │  " -ForegroundColor DarkGray -NoNewline
    Write-Host "[2]" -ForegroundColor Cyan -NoNewline
    Write-Host " Scan Multiple Domains (from file)                      │" -ForegroundColor White
    Write-Host "  │  " -ForegroundColor DarkGray -NoNewline
    Write-Host "[3]" -ForegroundColor Cyan -NoNewline
    Write-Host " Scan with Remediation Recommendations                  │" -ForegroundColor White
    Write-Host "  │  " -ForegroundColor DarkGray -NoNewline
    Write-Host "[4]" -ForegroundColor Cyan -NoNewline
    Write-Host " Quick Demo (5 well-known domains)                      │" -ForegroundColor White
    Write-Host "  ├───────────────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
    Write-Host "  │  " -ForegroundColor DarkGray -NoNewline
    Write-Host "DASHBOARD TESTING" -ForegroundColor Yellow -NoNewline
    Write-Host "                                            │" -ForegroundColor DarkGray
    Write-Host "  ├───────────────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
    Write-Host "  │  " -ForegroundColor DarkGray -NoNewline
    Write-Host "[5]" -ForegroundColor Cyan -NoNewline
    Write-Host " Launch Dashboard (Web Interface)                       │" -ForegroundColor White
    Write-Host "  │  " -ForegroundColor DarkGray -NoNewline
    Write-Host "[6]" -ForegroundColor Cyan -NoNewline
    Write-Host " Open Test Hub in Browser                               │" -ForegroundColor White
    Write-Host "  ├───────────────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
    Write-Host "  │  " -ForegroundColor DarkGray -NoNewline
    Write-Host "REPORTS & DATABASE" -ForegroundColor Yellow -NoNewline
    Write-Host "                                           │" -ForegroundColor DarkGray
    Write-Host "  ├───────────────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
    Write-Host "  │  " -ForegroundColor DarkGray -NoNewline
    Write-Host "[7]" -ForegroundColor Cyan -NoNewline
    Write-Host " View Latest Report                                     │" -ForegroundColor White
    Write-Host "  │  " -ForegroundColor DarkGray -NoNewline
    Write-Host "[8]" -ForegroundColor Cyan -NoNewline
    Write-Host " List All Reports                                       │" -ForegroundColor White
    Write-Host "  │  " -ForegroundColor DarkGray -NoNewline
    Write-Host "[9]" -ForegroundColor Cyan -NoNewline
    Write-Host " View Database Statistics                               │" -ForegroundColor White
    Write-Host "  ├───────────────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
    Write-Host "  │  " -ForegroundColor DarkGray -NoNewline
    Write-Host "TESTING & VERIFICATION" -ForegroundColor Yellow -NoNewline
    Write-Host "                                       │" -ForegroundColor DarkGray
    Write-Host "  ├───────────────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
    Write-Host "  │  " -ForegroundColor DarkGray -NoNewline
    Write-Host "[T]" -ForegroundColor Magenta -NoNewline
    Write-Host " Run Unit Tests                                         │" -ForegroundColor White
    Write-Host "  │  " -ForegroundColor DarkGray -NoNewline
    Write-Host "[H]" -ForegroundColor Magenta -NoNewline
    Write-Host " System Health Check                                    │" -ForegroundColor White
    Write-Host "  ├───────────────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
    Write-Host "  │  " -ForegroundColor DarkGray -NoNewline
    Write-Host "[Q]" -ForegroundColor Red -NoNewline
    Write-Host " Quit                                                   │" -ForegroundColor White
    Write-Host "  └───────────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""
}

function Scan-SingleDomain {
    Write-Host ""
    Write-Host "  Enter domain to scan (e.g., google.com, belfast.ac.uk):" -ForegroundColor Yellow
    Write-Host "  > " -NoNewline -ForegroundColor Cyan
    $domain = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($domain)) {
        Write-Warn "No domain entered."
        return
    }
    
    Write-Host ""
    Write-Info "Scanning $domain..."
    Write-Host ""
    
    Set-Location $SrcDir
    python -m app.cli --domain $domain
    
    Write-Host ""
    Write-Success "Scan complete!"
}

function Scan-MultipleDomains {
    Write-Host ""
    Write-Host "  Enter path to domains file (or press Enter for default domains.txt):" -ForegroundColor Yellow
    Write-Host "  > " -NoNewline -ForegroundColor Cyan
    $file = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($file)) {
        $file = $DomainsFile
    }
    
    if (-not (Test-Path $file)) {
        Write-Error "File not found: $file"
        return
    }
    
    $domainCount = (Get-Content $file | Where-Object { $_ -and -not $_.StartsWith("#") }).Count
    Write-Host ""
    Write-Info "Scanning $domainCount domains from $file..."
    Write-Host ""
    
    Set-Location $SrcDir
    python -m app.cli --domains $file
    
    Write-Host ""
    Write-Success "Batch scan complete!"
}

function Scan-WithRemediation {
    Write-Host ""
    Write-Host "  Enter domain to scan (e.g., google.com):" -ForegroundColor Yellow
    Write-Host "  > " -NoNewline -ForegroundColor Cyan
    $domain = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($domain)) {
        Write-Warn "No domain entered."
        return
    }
    
    Write-Host ""
    Write-Info "Scanning $domain with remediation recommendations..."
    Write-Host ""
    
    Set-Location $SrcDir
    python -m app.cli --domain $domain --remediation
    
    Write-Host ""
    Write-Success "Scan complete with remediation tips!"
}

function Run-QuickDemo {
    Write-Host ""
    Write-Info "Running quick demo scan of 5 well-known domains..."
    Write-Host ""
    
    # Create temp file with demo domains
    $tempFile = [System.IO.Path]::GetTempFileName()
    @"
# AuroraEdge Quick Demo - 5 Well-Known Domains
google.com
microsoft.com
github.com
amazon.com
cloudflare.com
"@ | Out-File -FilePath $tempFile -Encoding UTF8
    
    Set-Location $SrcDir
    python -m app.cli --domains $tempFile --remediation
    
    Remove-Item $tempFile -Force
    
    Write-Host ""
    Write-Success "Quick demo complete!"
}

function Launch-Dashboard {
    Write-Host ""
    Write-Info "Launching AuroraEdge Dashboard..."
    Write-Host ""
    Write-Host "  Dashboard will be available at: " -NoNewline
    Write-Host "http://127.0.0.1:8080" -ForegroundColor Green
    Write-Host "  Test Hub available at: " -NoNewline
    Write-Host "http://127.0.0.1:8080/test" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Press Ctrl+C to stop the server." -ForegroundColor DarkGray
    Write-Host ""
    
    # Open browser after a short delay
    Start-Job -ScriptBlock {
        Start-Sleep -Seconds 2
        Start-Process "http://127.0.0.1:8080"
    } | Out-Null
    
    Set-Location $SrcDir
    $env:DASH_TOKEN = ""
    python -m uvicorn app.dashboard:app --host 127.0.0.1 --port 8080
}

function Open-TestHub {
    Write-Host ""
    Write-Info "Opening Test Hub in default browser..."
    Start-Process "http://127.0.0.1:8080/test"
    Write-Success "Browser opened. Make sure dashboard is running (option 5)."
}

function View-LatestReport {
    Write-Host ""
    
    $reports = Get-ChildItem -Path $ReportsDir -Filter "*.md" -ErrorAction SilentlyContinue | 
               Sort-Object LastWriteTime -Descending |
               Select-Object -First 1
    
    if (-not $reports) {
        Write-Warn "No reports found. Run a scan first."
        return
    }
    
    Write-Info "Latest report: $($reports.Name)"
    Write-Host ""
    Write-Host (Get-Content $reports.FullName | Out-String) -ForegroundColor Gray
}

function List-AllReports {
    Write-Host ""
    
    $reports = Get-ChildItem -Path $ReportsDir -ErrorAction SilentlyContinue | 
               Sort-Object LastWriteTime -Descending
    
    if (-not $reports) {
        Write-Warn "No reports found."
        return
    }
    
    Write-Host "  ┌───────────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "  │  " -ForegroundColor DarkGray -NoNewline
    Write-Host "AVAILABLE REPORTS" -ForegroundColor Yellow -NoNewline
    Write-Host "                                            │" -ForegroundColor DarkGray
    Write-Host "  ├───────────────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
    
    foreach ($report in $reports) {
        $size = [math]::Round($report.Length / 1KB, 1)
        $date = $report.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
        $name = $report.Name.PadRight(40).Substring(0, 40)
        Write-Host "  │  $name  $date  ${size}KB" -ForegroundColor White
        Write-Host "    │" -ForegroundColor DarkGray
    }
    
    Write-Host "  └───────────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""
    Write-Info "Reports directory: $ReportsDir"
}

function View-DatabaseStats {
    Write-Host ""
    Write-Info "Fetching database statistics..."
    Write-Host ""
    
    Set-Location $SrcDir
    python -c @"
from app.database import get_database
db = get_database()
stats = db.get_statistics()
print(f'''
  Database Statistics
  ═══════════════════════════════════════
  Total Scans:        {stats.get('total_scans', 0)}
  Unique Domains:     {stats.get('unique_domains', 0)}
  Average Score:      {stats.get('avg_score', 0):.1f}
  
  Grade Distribution:
    A+/A: {stats.get('grade_a', 0)}
    B:    {stats.get('grade_b', 0)}
    C:    {stats.get('grade_c', 0)}
    D:    {stats.get('grade_d', 0)}
    F:    {stats.get('grade_f', 0)}
  ═══════════════════════════════════════
''')
"@
}

function Run-UnitTests {
    Write-Host ""
    Write-Info "Running unit tests..."
    Write-Host ""
    
    Set-Location $ProjectRoot
    python -m pytest tests/ -v --tb=short
    
    Write-Host ""
}

function Run-HealthCheck {
    Write-Host ""
    Write-Info "Running system health check..."
    Write-Host ""
    
    Set-Location $ProjectRoot
    python scripts/system_check.py
    
    Write-Host ""
}

function Wait-ForKey {
    Write-Host ""
    Write-Host "  Press any key to continue..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Main loop
function Main {
    # Activate virtual environment if it exists
    $venvActivate = Join-Path $ProjectRoot ".venv\Scripts\Activate.ps1"
    if (Test-Path $venvActivate) {
        . $venvActivate
    }
    
    while ($true) {
        Write-Header
        Show-Menu
        
        Write-Host "  Select option: " -NoNewline -ForegroundColor Yellow
        $choice = Read-Host
        
        switch ($choice.ToUpper()) {
            "1" { Scan-SingleDomain; Wait-ForKey }
            "2" { Scan-MultipleDomains; Wait-ForKey }
            "3" { Scan-WithRemediation; Wait-ForKey }
            "4" { Run-QuickDemo; Wait-ForKey }
            "5" { Launch-Dashboard }
            "6" { Open-TestHub; Wait-ForKey }
            "7" { View-LatestReport; Wait-ForKey }
            "8" { List-AllReports; Wait-ForKey }
            "9" { View-DatabaseStats; Wait-ForKey }
            "T" { Run-UnitTests; Wait-ForKey }
            "H" { Run-HealthCheck; Wait-ForKey }
            "Q" { 
                Write-Host ""
                Write-Host "  Goodbye! 👋" -ForegroundColor Cyan
                Write-Host ""
                exit 
            }
            default { 
                Write-Warn "Invalid option. Please try again."
                Start-Sleep -Seconds 1
            }
        }
    }
}

# Run main
Main
