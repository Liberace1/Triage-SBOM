#!/usr/bin/env bash
# TriageSBOM interactive setup (Linux / macOS / Git Bash on Windows).
# Asks how you want to run the app, then wires up that flow end to end and
# opens the browser for you:
#   - Docker:  ensure Docker is installed + running, build & start, open browser.
#   - Python:  ensure Python 3.11+, build the venv, install, test, launch UI.
# Run from the project folder:  ./setup.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DOCKER_URL="https://www.docker.com/products/docker-desktop/"
PYTHON_URL="https://www.python.org/downloads/"
APP_URL="http://localhost:8501"
DRY_RUN="${SETUP_DRY_RUN:-0}"   # set SETUP_DRY_RUN=1 to print the launch step instead of running it

open_url() {  # open a URL in the default browser, cross-platform
    local url="$1"
    if command -v xdg-open >/dev/null 2>&1; then xdg-open "$url" >/dev/null 2>&1 &
    elif command -v open >/dev/null 2>&1; then open "$url" >/dev/null 2>&1 &
    elif command -v cmd.exe >/dev/null 2>&1; then cmd.exe /c start "" "$url" >/dev/null 2>&1 &
    elif command -v powershell.exe >/dev/null 2>&1; then powershell.exe -NoProfile -Command "Start-Process '$url'" >/dev/null 2>&1 &
    else echo "Open this in your browser: $url"; fi
}

wait_for_app() {  # poll the Streamlit health endpoint, then open the browser
    echo "Waiting for the app to be ready..."
    if command -v curl >/dev/null 2>&1; then
        for _ in $(seq 1 60); do
            curl -fsS -o /dev/null "$APP_URL/_stcore/health" 2>/dev/null && break
            sleep 1
        done
    else
        sleep 10
    fi
    open_url "$APP_URL"
}

# --- Docker flow ---------------------------------------------------------------

try_install_docker() {  # returns 0 if an install was attempted successfully
    if command -v winget >/dev/null 2>&1; then
        read -r -p "Attempt automatic install via winget? [y/N] " a
        [[ "$a" =~ ^[Yy]$ ]] || return 1
        winget install -e --id Docker.DockerDesktop && return 0 || return 1
    elif command -v brew >/dev/null 2>&1; then
        read -r -p "Attempt automatic install via Homebrew? [y/N] " a
        [[ "$a" =~ ^[Yy]$ ]] || return 1
        brew install --cask docker && return 0 || return 1
    fi
    return 1
}

run_docker() {
    echo "=== Docker flow ==="
    if ! command -v docker >/dev/null 2>&1; then
        echo "Docker is not installed."
        if ! try_install_docker; then
            echo ""
            echo "Install Docker Desktop here:  $DOCKER_URL"
            echo "Click the link, install it, then START Docker Desktop and wait for it to say 'running'."
            read -r -p "Come back and press Enter once Docker is installed AND started... "
        fi
    fi
    if ! command -v docker >/dev/null 2>&1; then
        echo "Still can't find the 'docker' command."
        echo "If you just installed it, open a NEW terminal and re-run ./setup.sh"
        exit 1
    fi
    while ! docker info >/dev/null 2>&1; do
        echo ""
        echo "Docker is installed but the daemon isn't running yet."
        echo "Start Docker Desktop and wait until it reports 'running'."
        read -r -p "Press Enter to re-check (Ctrl+C to cancel)... "
    done
    echo "Docker is running."

    if [ "$DRY_RUN" = "1" ]; then
        echo "[dry-run] would run: docker compose up --build -d, then open the browser at $APP_URL"
        return
    fi
    echo "Building and starting the app (first build may take a few minutes)..."
    docker compose up --build -d
    wait_for_app
    echo ""
    echo "App is running at $APP_URL (a browser tab should have opened)."
    echo "  View logs:  docker compose logs -f"
    echo "  Stop:       docker compose down"
}

# --- Python flow ---------------------------------------------------------------

run_python() {
    echo "=== Python flow ==="
    local PY=""
    for c in python3 python py; do
        if command -v "$c" >/dev/null 2>&1; then
            ver="$("$c" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || true)"
            if [ -n "$ver" ]; then
                maj="${ver%%.*}"; min="${ver##*.}"
                if [ "$maj" -ge 3 ] && [ "$min" -ge 11 ]; then PY="$c"; break; fi
            fi
        fi
    done
    if [ -z "$PY" ]; then
        echo "Python 3.11+ was not found."
        echo "Install it here:  $PYTHON_URL"
        echo "Then open a NEW terminal and re-run ./setup.sh"
        exit 1
    fi
    echo "Python: $("$PY" --version) ($PY)"

    if [ ! -d venv ]; then
        echo "Creating virtual environment (venv/)..."
        "$PY" -m venv venv
    fi
    if [ -x venv/Scripts/python.exe ]; then VPY="venv/Scripts/python.exe"; else VPY="venv/bin/python"; fi

    echo "Installing dependencies..."
    "$VPY" -m pip install --upgrade pip >/dev/null
    "$VPY" -m pip install -e ".[dev]"

    echo "Running smoke test (pytest)..."
    "$VPY" -m pytest -q

    if [ "$DRY_RUN" = "1" ]; then
        echo "[dry-run] would run: $VPY -m streamlit run app.py --server.headless=false, opening the browser at $APP_URL"
        return
    fi
    echo "Starting the web UI (your browser will open at $APP_URL; Ctrl+C to stop)..."
    exec "$VPY" -m streamlit run app.py --server.headless=false
}

# --- Menu ----------------------------------------------------------------------

echo "=== TriageSBOM setup ==="
echo "How do you want to run TriageSBOM?"
echo "  [1] Docker  (containerized; only Docker required)"
echo "  [2] Python  (local virtual environment)"
while true; do
    read -r -p "Enter 1 or 2: " CHOICE
    case "$CHOICE" in
        1) run_docker; break ;;
        2) run_python; break ;;
        *) echo "Please enter 1 or 2." ;;
    esac
done
