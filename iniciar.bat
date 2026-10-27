@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo Ambiente Python ausente. Execute baixar.bat primeiro.
  pause
  exit /b 1
)
if not exist ".env" (
  echo Arquivo .env ausente. Execute baixar.bat primeiro.
  pause
  exit /b 1
)
if not exist "frontend\node_modules\vite\bin\vite.js" (
  echo Dependencias da interface ausentes. Execute baixar.bat primeiro.
  pause
  exit /b 1
)
where npm >nul 2>&1
if errorlevel 1 (
  echo npm nao encontrado. Instale Node.js e execute baixar.bat.
  pause
  exit /b 1
)

".venv\Scripts\python.exe" -m alembic upgrade head
if errorlevel 1 (
  echo Nao foi possivel preparar o banco de dados.
  pause
  exit /b 1
)

echo Iniciando SecureScan apenas em localhost...
start "SecureScan API" /D "%~dp0" cmd /k ""%~dp0.venv\Scripts\python.exe" -m uvicorn securescan.main:app --app-dir backend --host 127.0.0.1 --port 8000 --env-file .env"
if errorlevel 1 (
  echo Nao foi possivel iniciar a janela da API.
  pause
  exit /b 1
)
start "SecureScan Web" /D "%~dp0frontend" cmd /k "npm run dev"
if errorlevel 1 (
  echo Nao foi possivel iniciar a janela da interface.
  pause
  exit /b 1
)

echo API:       http://127.0.0.1:8000/docs
echo Interface: http://127.0.0.1:5173
echo Use Ctrl+C nas respectivas janelas para encerrar os servicos.
timeout /t 3 /nobreak >nul
start "" "http://127.0.0.1:5173"
exit /b 0
