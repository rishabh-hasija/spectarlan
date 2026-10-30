[CmdletBinding()]
param([switch]$Check)

$ErrorActionPreference = 'Stop'
$launcherExitCode = 1
$venvPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'

try {
    if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
        throw 'Local .venv is missing. Run: powershell -ExecutionPolicy Bypass -File setup_windows.ps1'
    }
    Push-Location -LiteralPath $PSScriptRoot
    try {
        & $venvPython -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw 'Python 3.11+ is required. Recreate .venv using setup_windows.ps1 with a supported Python.'
        }
        $dependencyCheck = @'
import sys
try:
    import streamlit, pandas, pydantic, psutil, httpx, platformdirs, specterlan
except Exception:
    sys.exit(1)
'@
        & $venvPython -c $dependencyCheck
        if ($LASTEXITCODE -ne 0) {
            throw 'Python dependencies are missing or broken. Run: powershell -ExecutionPolicy Bypass -File setup_windows.ps1'
        }
        if ($Check) {
            Write-Host 'SpecterLAN launcher check passed. Optional tools are checked in the app.'
            $launcherExitCode = 0
        } else {
            Write-Host 'SpecterLAN runs locally. Open the printed local URL. Ctrl+C stops it.'
            & $venvPython -m streamlit run app.py --server.address 127.0.0.1 --server.headless true --browser.gatherUsageStats false
            $launcherExitCode = $LASTEXITCODE
        }
    } finally {
        Pop-Location
    }
} catch {
    Write-Host ('SpecterLAN could not start. ' + $_.Exception.Message) -ForegroundColor Red
}
exit $launcherExitCode
