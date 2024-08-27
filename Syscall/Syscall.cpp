#include "Syscall.h"
#include "FunctionStub.h"
#include "syscallFunctionTemplates.h"
#include <iostream>

bool Syscall::bInitialized = false;
PLIST_ENTRY Syscall::pModuleList = nullptr;
PVOID Syscall::pLibraryBase = nullptr;
UINT_PTR Syscall::pIndirectSyscall = 0;
std::map<const char*, DWORD> Syscall::modules;
DWORD Syscall::lastSSN = 0;
constexpr int IN_MEMORY_ORDER_LINKS_OFFSET = sizeof(LIST_ENTRY); // 0x10


extern "C" {
	DWORD __ssn = 0;
	QWORD __pIndirectSyscall = 0;
}

Syscall::Syscall(const char* fnName) : ssn(0)
{
	if(!bInitialized)
	{
		Syscall::init();
	}

	if(pLibraryBase == nullptr)
	{
//#ifdef _DEBUG
		printf("[!] Module Base is null\n");
//#endif
		return;
	}

	PVOID pFunctionBase = Syscall::getExportAddress(pLibraryBase, fnName);
	if(pFunctionBase == nullptr)
	{
//#ifdef _DEBUG
		printf("[!] Function Base is null\n");
//#endif
		return;
	}

	this->ssn = Syscall::getSSN(pFunctionBase);
	if(this->ssn == 0)
	{
#ifdef _DEBUG
		printf("[!] SSN is null\n");
#endif
		return;
	}

	this->pIndirectSyscall = Syscall::getSyscallAddress(pFunctionBase);
	
	if(this->pIndirectSyscall == 0)
	{
		printf("[!] Indirect Syscall is null\n");
		return;
	}

	this->setSyscallAddress(this->pIndirectSyscall);

#ifdef _DEBUG
	printf("[+] SSN: 0x%x\n", this->ssn);
	printf("[+] Indirect Syscall: 0x%p\n", this->pIndirectSyscall);
#endif
}

void Syscall::setSyscallAddress(UINT_PTR ptr)
{
	__pIndirectSyscall = ptr;
}

void Syscall::setSSN()
{
	if(lastSSN == this->ssn)
	{
		return;
	}

	lastSSN = this->ssn;
	__ssn = this->ssn;
}

void Syscall::init()
{
	Syscall::findModules();
	Syscall::loadModule(L"ntdll.dll");
	Syscall::bInitialized = true;
}

void Syscall::findModules()
{
	PPEB peb = (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA pebLdrData = peb->Ldr;

#ifdef _DEBUG
	printf("[+] PEB Address: 0x%p\n", peb);
	printf("[+] PEB_LDR_DATA Address: 0x%x\n", pebLdrData);
#endif

	// get first address of the doubly-linked list
	Syscall::pModuleList = (&pebLdrData->InMemoryOrderModuleList);
}

void Syscall::loadModule(const wchar_t* name)
{
	constexpr int IN_MEMORY_ORDER_LINKS_OFFSET = sizeof(LIST_ENTRY); // 0x10

	// skip first entry (points to self)
	for(PLIST_ENTRY node = Syscall::pModuleList->Flink; node != Syscall::pModuleList; node = node->Flink)
	{
		PLDR_DATA_TABLE_ENTRY pTableEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)node - IN_MEMORY_ORDER_LINKS_OFFSET);
		wprintf(L"[+] DLL found: %-5s @ (%5s)\n", pTableEntry->BaseDllName.Buffer, pTableEntry->FullDllName.Buffer);

		if(pTableEntry->DllBase == nullptr)
		{
			printf("[!] DllBase is null\n");
			continue;
		}

		//TODO: Hash dll name
		if(wcscmp(name, pTableEntry->BaseDllName.Buffer) == 0)
		{
#ifdef _DEBUG
			printf("[+] Found Target DLL\n");
#endif
			Syscall::pLibraryBase = pTableEntry->DllBase;
			break;
		}
	}

	if(Syscall::pLibraryBase == nullptr)
	{
#ifdef _DEBUG
		printf("[!] Failed to find %ws\n", name);
#endif
		return;
	}
}

PVOID Syscall::getExportAddress(PVOID baseAddr, const char* functionName)
{
	const LPVOID pBaseAddr = (LPVOID)baseAddr;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddr;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)baseAddr + pDosHeader->e_lfanew);
	DWORD dwExportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)baseAddr + dwExportDirRVA);

#ifdef _DEBUG
	printf("[+] DOS Header: 0x%p\n", pDosHeader);
	printf("[+] NT Header: 0x%p\n", pNtHeaders);
	printf("[+] Export Directory: 0x%p\n", pExportDir);
#endif

	DWORD* pAddressOfFunctionsRVA = (DWORD*)((DWORD_PTR)baseAddr + pExportDir->AddressOfFunctions);
	DWORD* pAddressOfNamesRVA = (DWORD*)((DWORD_PTR)baseAddr + pExportDir->AddressOfNames);
	WORD* pAddressOfNameOrdinalsRVA = (WORD*)((DWORD_PTR)baseAddr + pExportDir->AddressOfNameOrdinals);

	for(DWORD i = 0; i < pExportDir->NumberOfFunctions; i++)
	{
		// function name
		DWORD_PTR dwFunctionNameRVA = pAddressOfNamesRVA[i];
		if(dwFunctionNameRVA == 0)
		{
			continue;
		}
		char* pFunctionName = (char*)((DWORD_PTR)baseAddr + dwFunctionNameRVA);

		//TODO: Hash function name
		if(strcmp(pFunctionName, functionName) == 0)
		{
			PVOID pFunctionBase = (PVOID)((DWORD_PTR)baseAddr + pAddressOfFunctionsRVA[pAddressOfNameOrdinalsRVA[i]]);
#ifdef _DEBUG
			printf("[+] Found Export \"%s\": 0x%p\n", functionName, pFunctionBase);
#endif
			return pFunctionBase;
		}
	}

	return nullptr;
}

UINT_PTR Syscall::getSyscallAddress(PVOID pFunctionBase)
{
	for(int i = 0; i < 0x30; i++)
	{
		PBYTE pCurrentByte = (PBYTE)pFunctionBase + i;
		if(*pCurrentByte == 0x0F && *(pCurrentByte + 1) == 0x05)
		{
			return (UINT_PTR)pCurrentByte;
		}
	}

	return 0;
}

_NODISCARD DWORD Syscall::searchSSN(PVOID pFunctionBase)
{
	constexpr BYTE syscallSignature[] = {
		0x4c, 0x8b, 0xd1, // mov r10, rcx
		0xb8, // mov eax, ? ? ? ?
	};

	// bitdefender EDR inserts JMP 
	constexpr BYTE JMP_INSTRUCTION = 0xE9;

	if(*(PBYTE)pFunctionBase == JMP_INSTRUCTION) {
		// function is hooked
	}
}

__forceinline _NODISCARD boolean Syscall::isHooked(PVOID pFunctionBase)
{

	// detect Bitdefender EDR hook
	// if first byte is JMP, then function is hooked
	if(*(PBYTE)pFunctionBase == 0xE9)
	{
		// e9 0b 02 18 00 == jmp QWORD PTR
		// E9 ?? ?? ?? ?? == sig

		// check surround exports
		// ntdll exports are spaced 0x20 bytes apart
		PVOID pPrevExport = (PBYTE)pFunctionBase - 0x20;
		PVOID pNextExport = (PBYTE)pFunctionBase + 0x20;


		return 0;
	}

	return FALSE;
}

__forceinline _NODISCARD DWORD Syscall::getSSN(PVOID pFunctionBase)
{
	constexpr BYTE syscallSignature[] = {
		0x4c, 0x8b, 0xd1, // mov r10, rcx
		0xb8, // mov eax, ? ? ? ?
	};


	// parse for EAX value

	BYTE ssn = 0;
	for(auto i = 0; i < 0x20; i++)
	{
		PBYTE pCurrentByte = (PBYTE)pFunctionBase + i;
		if(memcmp(pCurrentByte, syscallSignature, sizeof(syscallSignature)) == 0)
		{
			ssn = *(PBYTE)(pCurrentByte + sizeof(syscallSignature));
			break;
		}
	}


	return ssn;
}