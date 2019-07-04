;-----------------------------------------------------------------------------;
; Author: Ege Balcı <ege.balci[at]invictuseurope[dot]com>
; Compatible: Windows 10/8.1/8/7/2008/Vista/2003/XP/2000/NT4
; Version: 1.0 (25 January 2018)
; Size: 177 bytes
;-----------------------------------------------------------------------------;


[BITS 32]

  	pushad                 	        ; We preserve all the registers for the caller, bar EAX and ECX.
	mov eax,[fs:0x30]               ; PEB
	mov eax,[eax + 0x0c]            ; PEB_LDR_DATA
	mov eax,[eax + 0x0c]            ; InOrderModuleList
	mov dword [eax + 0x20],0xFFFFFF ; SizeOfImage
	popad                           ; Pop back all the registers
	ret                             ; <-
