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

	Syscall __NtOpenProcess("NtOpenProcess");

	HANDLE processHandle = NULL;

	CLIENT_ID clientId = { 0 };
	clientId.UniqueProcess = (HANDLE)notepadPid;
	clientId.UniqueThread = NULL;
	
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);

	printf("[+] Opening handle to Notepad process...\n");

	// call our custom syscall function
	NTSTATUS status = __NtOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &objectAttributes, &clientId);


}