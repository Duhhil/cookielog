#!/usr/bin/env python3
"""Test C: sink.py por named pipe real (cliente separado, protocolo do loader)."""
import json, sys, time
import ctypes
from ctypes import wintypes

PIPE = r"\\.\pipe\ck_pipe"
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
CreateFileW = k32.CreateFileW
CreateFileW.restype = wintypes.HANDLE
CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                        wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                        wintypes.HANDLE]
WriteFile = k32.WriteFile
WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_char_p, wintypes.DWORD,
                      ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
CloseHandle = k32.CloseHandle
INVALID = ctypes.c_void_p(-1).value


def send(payload, retries=20):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    for _ in range(retries):
        h = CreateFileW(PIPE, GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None)
        if h and h != INVALID:
            written = wintypes.DWORD(0)
            ok = WriteFile(h, data, len(data), ctypes.byref(written), None)
            CloseHandle(h)
            return ok, written.value
        time.sleep(0.25)
    raise SystemExit("pipe never appeared: %s" % ctypes.get_last_error())


if __name__ == "__main__":
    dump = json.load(open(sys.argv[1], encoding="utf-8"))
    print(send(dump))
