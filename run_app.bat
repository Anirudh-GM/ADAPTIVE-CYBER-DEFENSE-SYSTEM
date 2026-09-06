@echo off
echo Starting Adaptive Cyber Defense System...
echo.

if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
    streamlit run app.py
) else (
    python -m streamlit run app.py
)
pause

