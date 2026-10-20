// dllmain.cpp: DLL entry point for the ida-capa plugin (Windows only -- a Linux/Mac
// .so/.dylib plugin has no equivalent entry point to provide, so this file compiles
// to nothing there).
#include "pch.h"

#if defined(_WIN32)

BOOL APIENTRY DllMain(HMODULE /*module*/, DWORD reason, LPVOID /*reserved*/)
{
    switch ( reason )
    {
        case DLL_PROCESS_ATTACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

#endif  // _WIN32
