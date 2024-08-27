#pragma once
#ifndef __syscallFunctionTemplates_h
#define __syscallFunctionTemplates_h
#include <stdio.h>
#include <windows.h>

typedef unsigned __int64 QWORD;
typedef LONG NTSTATUS;

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define PROCESS_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)




// make take any parameters
//extern "C" NTSTATUS __fastcall NtApiStub();

//extern NTSTATUS NtCreateFile(
//	PHANDLE FileHandle, 
//	ACCESS_MASK DesiredAccess, 
//	POBJECT_ATTRIBUTES ObjectAttributes, 
//	PIO_STATUS_BLOCK IoStatusBlock, 
//	PLARGE_INTEGER AllocationSize, 
//	ULONG FileAttributes, 
//	ULONG ShareAccess, 
//	ULONG CreateDisposition, 
//	ULONG CreateOptions, 
//	PVOID EaBuffer, 
//	ULONG EaLength);
#endif // !__syscallFunctionTemplates_h