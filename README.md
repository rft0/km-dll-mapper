# Kernel Mode DLL Manual Mapper (KMDMM)

`src/km` -> Kernelmode driver
`src/um` -> Usermode program

## Build Requirements:
* Python 3+
* MSVC
* WDK

## Building
* In `build.bat`, set `WDK_INC`, `WDK_LIB` and `VS_PATH` depending on your setup.
* Run ```.\build km bytes``` to build kernelmode driver.
* Run ```.\build.bat um``` to build usermode program.
* Binary files for both driver and program is in `/bin` folder.