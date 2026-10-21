@echo off
cd /d "%~dp0"
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
echo [lu4loader console]
cl /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS lu4loader.c /Fe:lu4loader.exe /link user32.lib advapi32.lib shell32.lib psapi.lib ws2_32.lib
echo [lu4loader gui]
cl /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS lu4loader_gui.c /Fe:lu4loader_gui.exe /link user32.lib gdi32.lib advapi32.lib shell32.lib comctl32.lib psapi.lib ws2_32.lib
echo EXIT=%ERRORLEVEL%
