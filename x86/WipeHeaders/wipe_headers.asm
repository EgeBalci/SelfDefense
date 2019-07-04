;-----------------------------------------------------------------------------;
; Author: Ege Balcı <ege.balci[at]invictuseurope[dot]com>
; Compatible: Windows 10/8.1/8/7/2008/Vista/2003/XP/2000/NT4
; Version: 1.0 (25 January 2018)
; Size: 177 bytes
;-----------------------------------------------------------------------------;


[BITS 32]

  	pushad                 	; We preserve all the registers for the caller, bar EAX and ECX.
  	xor eax,eax           	; Zero EAX (upper 3 bytes will remain zero until function is found)
  	mov ebx,[fs:eax+0x30] 	; Get a pointer to the PEB
  	mov ebx,[ebx+0x0C]		; Get PEB->Ldr
	mov ebx,[ebx+0x14]		; Get the first module from the InMemoryOrder module list
	mov ebx,[ebx+0x10]		; Get this modules base address
	call block_api
	%include "../block_api.asm"
block_api:
	pop ebp                 ; Get the address of block_api to EBP
	mov ecx,0x1000          ; sizeof(PE_HEADERS)
	push dword 0x00         ; OldProtect
	push esp                ; lpflOldProtect
	push dword 0x04         ; flNewProtect (PAGE_READWRITE)
	push 0x1010             ; dwSize (Extra 0x10 bytes for safety)
	push ebx                ; lpAddress (EBX)
	push 0xC38AE110         ; hash( "KERNEL32.dll", "VirtualProtect" )
	call ebp                ; VirtualProtect()
wipe:
	mov dword [ebx],0x00    ; Wipe 1 byte
	inc ebx                 ; Increase EBX pointer
	loop wipe               ; Loop until ECX == 0
	popad                   ; Pop back all the registers
	ret                     ; <-
