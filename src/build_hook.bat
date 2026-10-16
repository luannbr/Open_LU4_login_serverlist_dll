@echo off
cd /d "%~dp0"
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cl /nologo /LD /O2 /EHsc /std:c++17 lu4authhook.cpp /Fe:lu4authhook.dll
echo EXIT=%ERRORLEVEL%
