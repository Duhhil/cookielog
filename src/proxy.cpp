// proxy.cpp - CRT-less DLL proxy entrypoint; link with ckdll.cpp.
// Build with proxy_entry as the DLL entrypoint. The original DLL's exports
// are supplied separately by the generated .def file.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

extern "C" DWORD WINAPI payload_entry(HINSTANCE h, DWORD reason, LPVOID reserved);

static DWORD WINAPI proxy_worker(LPVOID module)
{
    // Thread-style payload invocation; never run the payload under loader lock.
    payload_entry((HINSTANCE)(ULONG_PTR)1, 0, NULL);
    FreeLibraryAndExitThread((HMODULE)module, 0);
    return 0;
}

extern "C" BOOL WINAPI proxy_entry(HINSTANCE h, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        HMODULE module = NULL;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                               (LPCWSTR)&proxy_worker, &module)) {
            HANDLE thread = CreateThread(NULL, 0, proxy_worker, module, 0, NULL);
            if (thread)
                CloseHandle(thread);
            else
                FreeLibrary(module);
        }
        // A payload thread failure must not prevent the proxied DLL loading.
    }
    return TRUE;
}
