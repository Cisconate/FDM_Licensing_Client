$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

$venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"
$pythonExecutable = if (Test-Path -LiteralPath $venvPython) {
    $venvPython
} else {
    (Get-Command python -ErrorAction Stop).Source
}

& $pythonExecutable -m PyInstaller --noconfirm --clean --onedir `
    --name fdm-licensing --specpath build --workpath build\cli `
    --distpath dist fdm_licensing_cli.py
& $pythonExecutable -m PyInstaller --noconfirm --clean --onedir --windowed `
    --name FDM-Licensing-Client --specpath build --workpath build\gui `
    --distpath dist fdm_licensing_gui.py

Write-Host "Windows applications created under dist/."
