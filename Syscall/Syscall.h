#pragma once
#include <Windows.h>
#include "native.h"
#include <map>
#include <string>


extern "C" NTSTATUS __fastcall NtApiStub(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL
);

class Syscall
{
	private:
	static bool bInitialized;
	static PLIST_ENTRY pModuleList; // &PEB_LDR_DATA->InMemoryOrderModuleList
	static PVOID pLibraryBase;
	static UINT_PTR pIndirectSyscall;
	static std::map<const char*, DWORD> modules;
	static DWORD lastSSN;
	DWORD ssn;


	static void findModules();
	static void loadModule(const wchar_t* name);
	static PVOID getExportAddress(PVOID baseAddr, const char* functionName);
	static UINT_PTR getSyscallAddress(PVOID pFunctionBase);
	static DWORD getSSN(PVOID pFunctionBase);
	static void setSyscallAddress(UINT_PTR ptr);
	void setSSN();

	public:
	Syscall(const char* fnName);

	Syscall(const Syscall&) = delete;
	Syscall(Syscall&&) = delete;
	Syscall& operator=(const Syscall&) = delete;
	Syscall& operator=(Syscall&&) = delete;
	~Syscall() = default;


	template<typename... Args>
	NTSTATUS operator()(Args... args)
	{
#ifdef _DEBUG
		printf("[+] Changing SSN: 0x%x\n", this->ssn);
		printf("[+] Calling NtApiStub\n");
#endif
		this->setSSN();

		// call NtApiStub with our args
		NTSTATUS status = NtApiStub(args...);
		return status;
	}

	static void init();
};