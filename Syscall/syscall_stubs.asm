PUBLIC NtApiStub

.data

extern __ssn: DWORD
extern __pIndirectSyscall: QWORD

.code
NtApiStub PROC
	mov r10, rcx ;TODO: obfuscate
	mov eax, __ssn
	jmp qword ptr __pIndirectSyscall
	ret
NtApiStub ENDP

END