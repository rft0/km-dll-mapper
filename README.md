# Kernel Mode DLL Manual Mapper (KMDMM)
DLL Manual Mapper that uses windows kernel api methods to manipulate memory, change memory region rights etc\
UM program uses IOCTL to communicate with KM driver. 

![Kernelmode DLL Manual Mapper](https://raw.githubusercontent.com/rft0/km-dll-mapper/refs/heads/main/img/ss0.png)

`src/km` -> Kernelmode driver \
`src/um` -> Usermode program

## Build Requirements:
* Python 3+
* MSVC
* WDK

## Building
* In `build.bat`, set `WDK_INC`, `WDK_LIB` and `VS_PATH` depending on your setup.
* Run following command to build kernelmode driver and generate its byte array.
```
.\build km bytes
```
* Run following command to build usermode program.
```
.\build.bat um
```
* Binary files for both driver and program is in `/bin` folder.