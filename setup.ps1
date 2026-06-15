# TriageSBOM interactive setup (Windows PowerShell).
# Asks how you want to run the app, then wires up that flow end to end and
# opens the browser for you:
#   - Docker:  ensure Docker is installed + running, build & start, open browser.
#   - Python:  ensure Python 3.11+, build the venv, install, test, launch UI.
# Run from the project folder:  .\setup.ps1
# If blocked: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$DockerUrl = "https://www.docker.com/products/docker-desktop/"
$PythonUrl = "https://www.python.org/downloads/"
$AppUrl    = "http://localhost:8501"
$DryRun    = ($env:SETUP_DRY_RUN -eq "1")   # set SETUP_DRY_RUN=1 to print the launch step instead of running it

function Wait-ForApp {
    Write-Host "Waiting for the app to be ready..."
    for ($i = 0; $i -lt 60; $i++) {
        try {
            $r = Invoke-WebRequest -Uri "$AppUrl/_stcore/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
            if ($r.StatusCode -eq 200) { break }
        } catch { Start-Sleep -Seconds 1 }
    }
    Start-Process $AppUrl
}

# --- Docker flow ---------------------------------------------------------------

function Invoke-DockerInstall {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        $a = Read-Host "Attempt automatic install via winget? [y/N]"
        if ($a -match '^[Yy]$') {
            winget install -e --id Docker.DockerDesktop
            return ($LASTEXITCODE -eq 0)
        }
    }
    return $false
}

function Start-DockerFlow {
    Write-Host "=== Docker flow ===" -ForegroundColor Cyan
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Host "Docker is not installed."
        if (-not (Invoke-DockerInstall)) {
            Write-Host ""
            Write-Host "Install Docker Desktop here:  $DockerUrl" -ForegroundColor Yellow
            Write-Host "Click the link, install it, then START Docker Desktop and wait for it to say 'running'."
            Read-Host "Come back and press Enter once Docker is installed AND started"
        }
    }
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Host "Still can't find the 'docker' command." -ForegroundColor Red
        Write-Host "If you just installed it, open a NEW terminal and re-run .\setup.ps1"
        exit 1
    }
    while ($true) {
        docker info *> $null
        if ($LASTEXITCODE -eq 0) { break }
        Write-Host ""
        Write-Host "Docker is installed but the daemon isn't running yet."
        Write-Host "Start Docker Desktop and wait until it reports 'running'."
        Read-Host "Press Enter to re-check (Ctrl+C to cancel)"
    }
    Write-Host "Docker is running."

    if ($DryRun) {
        Write-Host "[dry-run] would run: docker compose up --build -d, then open the browser at $AppUrl"
        return
    }
    Write-Host "Building and starting the app (first build may take a few minutes)..."
    docker compose up --build -d
    Wait-ForApp
    Write-Host ""
    Write-Host "App is running at $AppUrl (a browser tab should have opened)."
    Write-Host "  View logs:  docker compose logs -f"
    Write-Host "  Stop:       docker compose down"
}

# --- Python flow ---------------------------------------------------------------

function Start-PythonFlow {
    Write-Host "=== Python flow ===" -ForegroundColor Cyan
    $py = $null
    foreach ($cmd in @("py", "python", "python3")) {
        $exe = (Get-Command $cmd -ErrorAction SilentlyContinue)
        if ($null -eq $exe) { continue }
        try { $ver = & $cmd -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null } catch { continue }
        if ($ver -match '^(\d+)\.(\d+)$' -and [int]$Matches[1] -ge 3 -and [int]$Matches[2] -ge 11) { $py = $cmd; break }
    }
    if ($null -eq $py) {
        Write-Host "Python 3.11+ was not found." -ForegroundColor Red
        Write-Host "Install it here:  $PythonUrl"
        Write-Host "Then open a NEW terminal and re-run .\setup.ps1"
        exit 1
    }
    Write-Host "Python: $(& $py --version) ($py)"

    if (-not (Test-Path "venv")) {
        Write-Host "Creating virtual environment (venv/)..."
        & $py -m venv venv
    }
    $vpy = ".\venv\Scripts\python.exe"

    Write-Host "Installing dependencies..."
    & $vpy -m pip install --upgrade pip | Out-Null
    & $vpy -m pip install -e ".[dev]"

    Write-Host "Running smoke test (pytest)..."
    & $vpy -m pytest -q

    if ($DryRun) {
        Write-Host "[dry-run] would run: $vpy -m streamlit run app.py --server.headless=false, opening the browser at $AppUrl"
        return
    }
    Write-Host "Starting the web UI (your browser will open at $AppUrl; Ctrl+C to stop)..."
    & $vpy -m streamlit run app.py --server.headless=false
}

# --- Menu ----------------------------------------------------------------------

Write-Host "=== TriageSBOM setup ===" -ForegroundColor Cyan
Write-Host "How do you want to run TriageSBOM?"
Write-Host "  [1] Docker  (containerized; only Docker required)"
Write-Host "  [2] Python  (local virtual environment)"
while ($true) {
    $choice = Read-Host "Enter 1 or 2"
    if ($choice -eq "1") { Start-DockerFlow; break }
    elseif ($choice -eq "2") { Start-PythonFlow; break }
    else { Write-Host "Please enter 1 or 2." }
}
