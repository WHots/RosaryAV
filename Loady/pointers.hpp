#pragma once
#include <Windows.h>
#include <winternl.h>
#include "ntdll.h"



namespace pointers
{

	typedef NTSTATUS(NTAPI* fpNtReadVirtualMemory)(HANDLE ProcessHandle,PVOID BaseAddress,PVOID Buffer,ULONG NumberOfBytesToRead,PULONG NumberOfBytesReaded);
    typedef NTSTATUS(WINAPI* pNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass,PVOID SystemInformation,ULONG SystemInformationLength,PULONG ReturnLength);
    typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(ULONG SystemInformationClass,PVOID SystemInformation,ULONG SystemInformationLength,PULONG ReturnLength);
    typedef NTSTATUS(NTAPI* fpNtQueryInformationThread)(HANDLE ThreadHandle,THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
    typedef NTSTATUS(NTAPI* fpNtPrivilegeCheck)(HANDLE ClientToken, PPRIVILEGE_SET RequiredPrivileges, PBOOLEAN Result);
    typedef NTSTATUS(WINAPI* fpLdrQueryProcessModuleInformation)(PLDR_MODULE ModuleInformation,ULONG SizeOfModuleInformation,PULONG ReturnedSize);

    typedef NTSTATUS(WINAPI* fpNtQueryVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

	using TNtQueryInformationProcess = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
}