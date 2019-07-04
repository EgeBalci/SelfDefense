;-----------------------------------------------------------------------------;
; Author: Ege Balcı <ege.balci[at]invictuseurope[dot]com>
; Compatible: Windows 10/8.1/8/7/2008/Vista/2003/XP/2000/NT4
; Version: 1.0 (25 January 2018)
; Size: 177 bytes
;-----------------------------------------------------------------------------;


[BITS 64]

	xor rax,rax
	mov rax, [gs:rax+96]             ; PEB
	mov rax, [rax+24]                ; PEB_LDR_DATA
	mov rax, [rax+32]                ; InOrderModuleList
	mov dword [rax + 0x40],0xFFFFFF  ; SizeOfImage
	ret                              ; <-
