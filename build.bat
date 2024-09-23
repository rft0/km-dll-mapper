@echo off
setlocal

set WDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0
set WDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\km\x64

set VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community

if not exist bin mkdir bin
if not exist obj mkdir obj
if not exist obj\um mkdir obj\um
if not exist obj\km mkdir obj\km

call "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1

if "%~1"=="" (
    echo Please specify "km" for kernel-mode or "um" for user-mode.
    exit /b 1
)

if /I "%~1"=="km" (
    cl /D_AMD64_ /GS- /DRIVER /KERNEL src\km\*.c /c /Foobj\km\ /I"%WDK_INC%\km"
    link /LIBPATH:"%WDK_LIB%" NtosKrnl.lib obj\km\*.obj /DRIVER /KERNEL /ENTRY:DriverEntry /SUBSYSTEM:NATIVE /OUT:bin\out.sys /NODEFAULTLIB:LIBCMT /NODEFAULTLIB:MSVCRT /NODEFAULTLIB:ALL

    if /I "%~2"=="bytes" py bytes.py bin\out.sys src\um\mapper\driver_res.cpp

) else if /I "%~1"=="um" (
    cl /EHsc /std:c++17 /c /Foobj\um\ src\um\*.cpp src\um\mapper\*.cpp /Fe:bin\out.exe
    link Advapi32.lib user32.lib /SUBSYSTEM:CONSOLE /OUT:bin\out.exe obj\um\*.obj
    @REM .\bin\out.exe
)

endlocal
