$b = [IO.File]::ReadAllBytes("$PSScriptRoot\..\bin\ckdll.dll")
$s = ($b | ForEach-Object { "0x{0:x2}" -f $_ }) -join ","
Set-Content -Encoding ascii "$PSScriptRoot\payload.h" `
  "#pragma once`nstatic unsigned char g_payload[] = {$s};`nstatic unsigned g_payload_len = $($b.Length);`n#define PAYLOAD_ENTRY `"payload_entry`""
