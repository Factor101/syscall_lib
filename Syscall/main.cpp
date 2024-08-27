#include <iostream>
#include "Syscall.h"
#include "native.h"
#include "FunctionStub.h"
#include "syscallFunctionTemplates.h"
#include <cstdio>
#define _DEBUG 1
#pragma comment( lib, "ntdll" )

extern "C" NTSYSAPI VOID NTAPI RtlInitUnicodeString(
	_Out_ PUNICODE_STRING DestinationString,
	_In_opt_ PWSTR SourceString
);

int main(int argc, char* argv[])
{
	Syscall::init();
	//Syscall __NtCreateUserProcess("NtCreateUserProcess");
	//HANDLE hProcess, hThread = NULL;
	//UNICODE_STRING imagePath = { 0 };
	//RtlInitUnicodeString(&imagePath, (PWSTR)L"\\??\\C:\\Windows\\System32\\notepad.exe");
	//PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
	////RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
	//exit(0);

	Syscall __NtOpenProcess("NtOpenProcess");

	DWORD notepadPid = 9088; // Replace with actual PID of Notepad
	HANDLE processHandle = NULL;

	CLIENT_ID clientId = { 0 };
	clientId.UniqueProcess = (HANDLE)notepadPid;
	clientId.UniqueThread = NULL;
	
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);

	printf("[+] Opening handle to Notepad process...\n");

	// call our custom syscall function
	NTSTATUS status = __NtOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &objectAttributes, &clientId);

	//HANDLE status = OpenProcess(PROCESS_ALL_ACCESS, true, notepadPid);
	exit(0);
	//if(status == STATUS_SUCCESS) {
	//	//printf("[+] Successfully opened handle to Notepad process\n");
	//	BOOL result = TerminateProcess(processHandle, 1);
	//	if(result != 0) {
	//		printf("[+] Successfully terminated Notepad process\n");
	//	} else {
	//		printf("[!] Failed to terminate Notepad process\n");
	//	}
	//	CloseHandle(processHandle);
	//} else {
	//	printf("[!] Failed to open handle to Notepad process\n");
	//}

	//exit(0);
}