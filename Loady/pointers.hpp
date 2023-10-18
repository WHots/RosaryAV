#pragma once
#include <Windows.h>
#include <winternl.h>

#include "ntdll.h"


namespace pointers
{

	typedef NTSTATUS(NTAPI* fpNtReadVirtualMemory)(HANDLE ProcessHandle,PVOID BaseAddress,PVOID Buffer,ULONG NumberOfBytesToRead,PULONG NumberOfBytesReaded);
    typedef NTSTATUS(WINAPI* pNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass,PVOID SystemInformation,ULONG SystemInformationLength,PULONG ReturnLength);
    typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(ULONG SystemInformationClass,PVOID SystemInformation,ULONG SystemInformationLength,PULONG ReturnLength);
    typedef NTSTATUS(NTAPI* fpNtPrivilegeCheck)(HANDLE ClientToken, PPRIVILEGE_SET RequiredPrivileges, PBOOLEAN Result);
    typedef NTSTATUS(WINAPI* fpLdrQueryProcessModuleInformation)(PLDR_MODULE ModuleInformation,ULONG SizeOfModuleInformation,PULONG ReturnedSize);

	using TNtQueryInformationProcess = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
}