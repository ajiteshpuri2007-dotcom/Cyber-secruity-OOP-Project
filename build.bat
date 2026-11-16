@echo off
setlocal
cd /d "%~dp0"
set PATH=C:\msys64\ucrt64\bin;%PATH%
C:\msys64\ucrt64\bin\mingw32-make.exe all
