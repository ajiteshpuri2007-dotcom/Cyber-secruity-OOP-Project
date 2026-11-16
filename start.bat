@echo off
setlocal
cd /d "%~dp0"
set PATH=C:\msys64\ucrt64\bin;%PATH%
if not exist "build\privy_server.exe" (
    call build.bat
    if errorlevel 1 goto :eof
)
echo Starting PRiVY backend server on http://localhost:3000 ...
build\privy_server.exe 3000 privy.db
