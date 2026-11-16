@echo off
setlocal

REM PRiVY Windows Build Script
REM Uses MSYS2 UCRT64 g++ (C:\msys64\ucrt64\bin)
REM Run this from the "oops project" directory.

set MSYS2_BIN=C:\msys64\ucrt64\bin
set PATH=%MSYS2_BIN%;%PATH%

set SRC=src
set BUILD=build

set CXXFLAGS=-std=c++17 -Wall -O2 -I%SRC% -I%MSYS2_BIN%\..\include
set CFLAGS=-O2 -I%SRC%
set LDFLAGS=-L%MSYS2_BIN%\..\lib
set LIBS=-lssl -lcrypto -lws2_32 -lbcrypt

REM Create build dir
if not exist %BUILD% mkdir %BUILD%

echo [1/8] Compiling SQLite amalgamation (C) - this may take a moment...
gcc %CFLAGS% -c %SRC%\sq3lite.c -o %BUILD%\sq3lite.o
if errorlevel 1 ( echo FAILED: SQLite amalgamation & goto :err )

echo [2/8] Compiling User.cpp...
g++ %CXXFLAGS% -c %SRC%\User.cpp -o %BUILD%\User.o
if errorlevel 1 ( echo FAILED: User.cpp & goto :err )

echo [3/8] Compiling Admin.cpp...
g++ %CXXFLAGS% -c %SRC%\Admin.cpp -o %BUILD%\Admin.o
if errorlevel 1 ( echo FAILED: Admin.cpp & goto :err )

echo [4/8] Compiling ScanResult.cpp...
g++ %CXXFLAGS% -c %SRC%\ScanResult.cpp -o %BUILD%\ScanResult.o
if errorlevel 1 ( echo FAILED: ScanResult.cpp & goto :err )

echo [5/8] Compiling URLAnalyzer.cpp...
g++ %CXXFLAGS% -c %SRC%\URLAnalyzer.cpp -o %BUILD%\URLAnalyzer.o
if errorlevel 1 ( echo FAILED: URLAnalyzer.cpp & goto :err )

echo [6/8] Compiling PhishingDetector.cpp...
g++ %CXXFLAGS% -c %SRC%\PhishingDetector.cpp -o %BUILD%\PhishingDetector.o
if errorlevel 1 ( echo FAILED: PhishingDetector.cpp & goto :err )

echo [7/8] Compiling api_server.cpp...
g++ %CXXFLAGS% -c %SRC%\api_server.cpp -o %BUILD%\api_server.o
if errorlevel 1 ( echo FAILED: api_server.cpp & goto :err )

echo [8/8] Compiling main.cpp...
g++ %CXXFLAGS% -c %SRC%\main.cpp -o %BUILD%\main.o
if errorlevel 1 ( echo FAILED: main.cpp & goto :err )

echo [Link] Linking privy_engine.exe (OOP demo)...
g++ %CXXFLAGS% %LDFLAGS% -o %BUILD%\privy_engine.exe ^
    %BUILD%\main.o %BUILD%\User.o %BUILD%\Admin.o ^
    %BUILD%\ScanResult.o %BUILD%\URLAnalyzer.o %BUILD%\PhishingDetector.o
if errorlevel 1 ( echo FAILED: Linking engine & goto :err )

echo [Link] Linking privy_server.exe (HTTP backend)...
g++ %CXXFLAGS% %LDFLAGS% -o %BUILD%\privy_server.exe ^
    %BUILD%\api_server.o %BUILD%\sq3lite.o ^
    %BUILD%\User.o %BUILD%\Admin.o %BUILD%\ScanResult.o ^
    %BUILD%\URLAnalyzer.o %BUILD%\PhishingDetector.o ^
    %LIBS%
if errorlevel 1 ( echo FAILED: Linking server & goto :err )

echo.
echo ============================================
echo  BUILD SUCCESSFUL!
echo ============================================
echo  Engine : %BUILD%\privy_engine.exe
echo  Server : %BUILD%\privy_server.exe
echo.
echo  To start the server:
echo    build\privy_server.exe 3000 privy.db
echo.
echo  Then open: http://localhost:3000
echo ============================================
goto :eof

:err
echo.
echo BUILD FAILED - check the error message above.
exit /b 1
