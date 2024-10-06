PUBLIC NtApiStub

.data

extern __ssn: DWORD
extern __pIndirectSyscall: QWORD
; 10 arg slots

.code
NtApiStub PROC
	;mov r10, rcx TODO: obfuscate
	push rcx
	mov eax, __ssn
	jmp qword ptr __pIndirectSyscall
	pop rcx 
	ret
NtApiStub ENDP

NtApiStubDynamicArgs PROC
; x64 __fastcall calling convention = first 5 on registers (rcx, rdx, r8-r10), then stack (FILO)

	

NtApiStubDynamicArgs ENDP


END