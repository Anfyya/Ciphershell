@echo off
chcp 65001 >nul
set "LOG=D:\vscode\CipherShell\build_log.txt"
echo [BUILD START] %date% %time% > "%LOG%"

:: 查找 VS2022 vcvarsall.bat
set "VCVARS="
for %%E in (Community Professional Enterprise BuildTools) do (
    if exist "C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvarsall.bat" (
        set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvarsall.bat"
        echo Found VS2022 %%E >> "%LOG%"
        goto :found
    )
)
echo ERROR: VS2022 not found >> "%LOG%"
goto :eof

:found
call "%VCVARS%" x64 >> "%LOG%" 2>&1

cd /d "D:\vscode\CipherShell"
if exist build_vs rd /s /q build_vs
mkdir build_vs
cd build_vs

echo. >> "%LOG%"
echo [CMAKE CONFIGURE] >> "%LOG%"
cmake .. -G "Visual Studio 17 2022" -A x64 >> "%LOG%" 2>&1

echo. >> "%LOG%"
echo [CMAKE BUILD] >> "%LOG%"
cmake --build . --config Release >> "%LOG%" 2>&1
set BUILD_RESULT=%ERRORLEVEL%

echo. >> "%LOG%"
echo [BUILD RESULT] errorlevel=%BUILD_RESULT% >> "%LOG%"
echo. >> "%LOG%"

echo [EXE FILES] >> "%LOG%"
dir /s /b *.exe >> "%LOG%" 2>&1

echo. >> "%LOG%"
echo [BUILD END] %date% %time% >> "%LOG%"
exit
