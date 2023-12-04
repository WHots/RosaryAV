#pragma once
#include <Windows.h>
#include <winternl.h>

#include "ntdll.h"
#include "accctrl.h"



namespace prototypes
{
    using fpNtReadVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
    using fpNtQuerySystemInformation = NTSTATUS(NTAPI*)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
    using fpNtQueryInformationThread = NTSTATUS(NTAPI*)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
    using fpNtPrivilegeCheck = NTSTATUS(NTAPI*)(HANDLE ClientToken, PPRIVILEGE_SET RequiredPrivileges, PBOOLEAN Result);
    using fpLdrQueryProcessModuleInformation = NTSTATUS(WINAPI*)(PLDR_MODULE ModuleInformation, ULONG SizeOfModuleInformation, PULONG ReturnedSize);
    using fpNtOpenProcessToken = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);
    using fpNtQueryInformationToken = NTSTATUS(NTAPI*)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength);
    using fpNtQueryVirtualMemory = NTSTATUS(WINAPI*)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
    using fpNtQueryInformationProcess = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    using fpNtQueryInformationThread = NTSTATUS(WINAPI*)(HANDLE ThreadHandle,THREADINFOCLASS ThreadInformationClass,PVOID ThreadInformation,ULONG ThreadInformationLength,PULONG ReturnLength);
    using fpGetNamedSecurityInfoW = DWORD(WINAPI*)(LPCWSTR, SE_OBJECT_TYPE, SECURITY_INFORMATION, PSID*, PSID*, PACL*, PACL*, PSECURITY_DESCRIPTOR*);
    using fpConvertSidToStringSidW = BOOL(WINAPI*)(PSID, LPTSTR*);
}



