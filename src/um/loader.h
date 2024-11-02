#ifndef __LOADER_H
#define __LOADER_H

#include <Windows.h>

#include "mapper/kdmapper.hpp"
#include "mapper/driver_res.hpp"

namespace Loader {
    void LoadDriver();
    void UnloadDriver();

    void EnableCrashHandler();
}

#endif