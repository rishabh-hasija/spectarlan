[CmdletBinding()]
param(
    [string]$Python = '',
    [switch]$Dev
)

$ErrorActionPreference = 'Stop'
$setupExitCode = 1
$venvPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'

try {
    Push-Location -LiteralPath $PSScriptRoot
    try {
        if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
            $bootstrapArgs = @()
            if ($Python) {
                $bootstrapPython = $Python
            } elseif (Get-Command py.exe -CommandType Application -ErrorAction SilentlyContinue) {
                $bootstrapPython = 'py.exe'
                $bootstrapArgs = @('-3')
            } elseif (Get-Command python.exe -CommandType Application -ErrorAction SilentlyContinue) {
                $bootstrapPython = 'python.exe'
            } else {
                throw 'Install Python 3.11+ from https://www.python.org/downloads/windows/, then rerun setup. No system software was installed.'
            }
            & $bootstrapPython @bootstrapArgs -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>$null
            if ($LASTEXITCODE -ne 0) {
                throw 'Python 3.11+ is required. Use -Python with the path to a supported python.exe.'
            }
            & $bootstrapPython @bootstrapArgs -m venv .venv
            if ($LASTEXITCODE -ne 0) {
                throw 'Could not create .venv. Check checkout permissions and Python venv support.'
            }
        }
        & $venvPython -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw 'Existing .venv needs Python 3.11+. Rename it and rerun setup with a supported Python.'
        }
        $packageSpec = '.'
        if ($Dev) { $packageSpec = '.[dev]' }
        & $venvPython -m pip install -e $packageSpec
        if ($LASTEXITCODE -ne 0) {
            throw 'Dependency installation failed. Check internet access and retry setup; see pip output above.'
        }
        Write-Host 'Setup complete. SpecterLAN stores data locally in %LOCALAPPDATA%\SpecterLAN\.'
        Write-Host 'No registration or login. Demo Seance works without live discovery.'
        Write-Host 'Optional AI: install and open Ollama from https://ollama.com/download/windows, then run: ollama pull gemma3:4b'
        Write-Host 'Scanning and history work without Ollama. Nmap is recommended, not required: https://nmap.org/download.html'
        Write-Host 'Ollama and Nmap were not installed by this helper.'
        Write-Host 'Launch: powershell -ExecutionPolicy Bypass -File run_specterlan.ps1'
        $setupExitCode = 0
    } finally {
        Pop-Location
    }
} catch {
    Write-Host ('SpecterLAN setup failed. ' + $_.Exception.Message) -ForegroundColor Red
}
exit $setupExitCode
