@echo off
REM DoBot Shield Training Mode report generator.
REM Usage: generate_report.bat [-in logs\training.jsonl] [-out training-report.html]
setlocal
cd /d "%~dp0"

where go >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Go was not found in PATH. Install Go to generate the report.
  exit /b 1
)

echo Generating the DoBot Shield Training Mode report...
go run ./cmd/report -open %*
if errorlevel 1 (
  echo [ERROR] Report generation failed. Check the input log path and contents.
  exit /b 1
)

echo Done.
endlocal
