[BITS 32]
 
    cld                       ; Clear direction flags
    call start                ; Get the address of api block to stack
	%include "../block_api.asm"; https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_api.asm
start:
    pop ebp                   ; Pop the address of api block
	push 0x006c6c64           ; 0x00,lld
	push 0x2e6c6c64           ; .lld
    push 0x746e0000           ; nt,0x00
	lea eax,[esp+2]           ; Get the &"ntdll.dll" to eax
	push eax                  ; &"ntdll.dll"
	push 0x0726774C           ; hash( "KERNEL32.dll", "LoadLibraryA" )
	call ebp                  ; LoadLibraryA(&"ntdll.dll")
;-----------------------------;
	push 0x11D65D48           ; hash( "KERNEL32.dll", "GetCurrentThread" )
	call ebp                  ; GetCurrentThread()
	push dword 0x00           ; NULL
	push dword 0x00           ; NULL
	push dword 0x11           ; HideThreadFromDebugger
	push eax                  ; HANDLE
	push 0xC3813603           ; hash( "NTDLL.dll", "NtSetInformationThread" )
	call ebp                  ; NtSetInformationThread(ThreadHandle,0x11,0,0)
	add esp,0x0C              ; Fix the stack
	ret 
