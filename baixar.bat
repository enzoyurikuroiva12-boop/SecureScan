@echo off
setlocal
cd /d "%~dp0"

echo SecureScan - instalacao do ambiente local
echo.

where py >nul 2>&1
if errorlevel 1 (
  set "FAIL_REASON=Python Launcher (py) nao encontrado. Instale Python 3.11 ou superior."
  goto failed
)
py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)" >nul 2>&1
if errorlevel 1 (
  set "FAIL_REASON=Python 3.11 ou superior nao encontrado."
  goto failed
)

where node >nul 2>&1
if errorlevel 1 (
  set "FAIL_REASON=Node.js nao encontrado. Instale Node.js 20.19+ ou 22.12+ e execute este arquivo novamente."
  goto failed
)
where npm >nul 2>&1
if errorlevel 1 (
  set "FAIL_REASON=npm nao encontrado. Reinstale o Node.js incluindo o npm."
  goto failed
)

if not exist ".venv\Scripts\python.exe" (
  echo Criando ambiente Python...
  py -3 -m venv .venv
  if errorlevel 1 (
    set "FAIL_REASON=Nao foi possivel criar o ambiente virtual Python."
    goto failed
  )
)

echo Instalando dependencias da API e dos testes...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
  set "FAIL_REASON=A instalacao das dependencias Python falhou. Verifique a conexao e tente novamente."
  goto failed
)

echo Instalando scanners opcionais pip-audit e Bandit...
".venv\Scripts\python.exe" -m pip install "pip-audit>=2.10.1,<3" "bandit>=1.8,<2"
if errorlevel 1 (
  set "FAIL_REASON=Nao foi possivel instalar pip-audit e Bandit. Verifique a conexao e tente novamente."
  goto failed
)

if not exist ".env" (
  copy /Y ".env.example" ".env" >nul
  if errorlevel 1 (
    set "FAIL_REASON=Nao foi possivel criar .env a partir de .env.example."
    goto failed
  )
)

echo Preparando o banco de dados...
".venv\Scripts\python.exe" -m alembic upgrade head
if errorlevel 1 (
  set "FAIL_REASON=A migracao do banco falhou."
  goto failed
)

echo Instalando dependencias da interface...
pushd frontend
call npm install
set "NPM_EXIT=%ERRORLEVEL%"
popd
if not "%NPM_EXIT%"=="0" (
  set "FAIL_REASON=A instalacao das dependencias da interface falhou."
  goto failed
)

echo.
echo Instalacao concluida. Execute iniciar.bat para abrir o SecureScan.
pause
exit /b 0

:failed
echo.
echo ERRO: %FAIL_REASON%
pause
exit /b 1
