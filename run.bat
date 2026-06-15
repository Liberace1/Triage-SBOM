@echo off
REM Quick start script for TriageSBOM Streamlit UI (Windows)

cd /d "%~dp0"

echo TriageSBOM Streamlit UI — Starting...

REM Create venv if missing
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate venv
call venv\Scripts\activate.bat

REM Install/upgrade dependencies
echo Installing dependencies...
python -m pip install --upgrade pip
python -m pip install -e ".[ui]"

REM Run Streamlit app
echo.
echo 🚀 Launching at http://localhost:8501
echo Press Ctrl+C to stop.
echo.
streamlit run app.py --server.port=8501
