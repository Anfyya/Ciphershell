@echo off
setlocal EnableExtensions
chcp 65001 >nul

set "ROOT=%~dp0"
set "ROOT=%ROOT:~0,-1%"
set "BUILD_DIR=%ROOT%\build"
set "CONFIG=%~1"
if not defined CONFIG set "CONFIG=Release"

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
set "CS_BUILD_LOG_FILE=%BUILD_DIR%\build_%CONFIG%.log"
echo [BUILD START] %date% %time%>"%CS_BUILD_LOG_FILE%"

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VSROOT="
if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSROOT=%%I"
)

if not defined VSROOT (
    for %%E in (BuildTools Community Professional Enterprise) do (
        if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvarsall.bat" set "VSROOT=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\%%E"
        if exist "%ProgramFiles%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvarsall.bat" set "VSROOT=%ProgramFiles%\Microsoft Visual Studio\2022\%%E"
    )
)

if not defined VSROOT (
    echo ERROR: Visual Studio 2022 C++ toolchain was not found.>>"%CS_BUILD_LOG_FILE%"
    type "%CS_BUILD_LOG_FILE%"
    exit /b 1
)

call "%VSROOT%\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 goto :failed

set "CMAKE_EXE=%VSROOT%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if not exist "%CMAKE_EXE%" (
    for /f "delims=" %%I in ('where cmake.exe 2^>nul') do if not defined CMAKE_EXE set "CMAKE_EXE=%%I"
)
if not exist "%CMAKE_EXE%" (
    echo ERROR: CMake was not found.>>"%CS_BUILD_LOG_FILE%"
    goto :failed
)

if not defined CS_NASM_EXECUTABLE (
    for /f "delims=" %%I in ('where nasm.exe 2^>nul') do if not defined CS_NASM_EXECUTABLE set "CS_NASM_EXECUTABLE=%%I"
)
if not exist "%CS_NASM_EXECUTABLE%" (
    echo ERROR: NASM was not found. Install NASM or set CS_NASM_EXECUTABLE.>>"%CS_BUILD_LOG_FILE%"
    goto :failed
)

echo [CMAKE CONFIGURE]>>"%CS_BUILD_LOG_FILE%"
"%CMAKE_EXE%" -S "%ROOT%" -B "%BUILD_DIR%" -G "Visual Studio 17 2022" -A x64 "-DCS_NASM_EXECUTABLE=%CS_NASM_EXECUTABLE%" >>"%CS_BUILD_LOG_FILE%" 2>&1
if errorlevel 1 goto :failed

echo [CMAKE BUILD]>>"%CS_BUILD_LOG_FILE%"
"%CMAKE_EXE%" --build "%BUILD_DIR%" --config "%CONFIG%" -- /m >>"%CS_BUILD_LOG_FILE%" 2>&1
if errorlevel 1 goto :failed

echo [BUILD PASS] %date% %time%>>"%CS_BUILD_LOG_FILE%"
type "%CS_BUILD_LOG_FILE%"
exit /b 0

:failed
set "RESULT=%ERRORLEVEL%"
if "%RESULT%"=="0" set "RESULT=1"
echo [BUILD FAIL] errorlevel=%RESULT% %date% %time%>>"%CS_BUILD_LOG_FILE%"
type "%CS_BUILD_LOG_FILE%"
exit /b %RESULT%
