#!/usr/bin/env bash
# Quick start script for TriageSBOM Streamlit UI (Linux/macOS)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "TriageSBOM Streamlit UI — Starting..."

# Create venv if missing
if [ ! -d venv ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate venv
source venv/bin/activate

# Install/upgrade dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -e ".[ui]"

# Run Streamlit app
echo ""
echo "🚀 Launching at http://localhost:8501"
echo "Press Ctrl+C to stop."
echo ""
streamlit run app.py --server.port=8501
