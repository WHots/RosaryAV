#pragma once
#include <Windows.h>
#include <winternl.h>

#include "ntdll.h"
#include "accctrl.h"




//namespace types
//{
//    typedef enum _SE_OBJECT_TYPE
//    {
//        SE_UNKNOWN_OBJECT_TYPE = 0,
//        SE_FILE_OBJECT,
//        SE_SERVICE,
//        SE_PRINTER,
//        SE_REGISTRY_KEY,
//        SE_LMSHARE,
//        SE_KERNEL_OBJECT,
//        SE_WINDOW_OBJECT,
//        SE_DS_OBJECT,
//        SE_DS_OBJECT_ALL,
//        SE_PROVIDER_DEFINED_OBJECT,
//        SE_WMIGUID_OBJECT,
//        SE_REGISTRY_WOW64_32KEY
//
//    } SE_OBJECT_TYPE;
//}




namespace prototypes
{
	typedef NTSTATUS(NTAPI* fpNtReadVirtualMemory)(HANDLE ProcessHandle,PVOID BaseAddress,PVOID Buffer,ULONG NumberOfBytesToRead,PULONG NumberOfBytesReaded);
    typedef NTSTATUS(WINAPI* pNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass,PVOID SystemInformation,ULONG SystemInformationLength,PULONG ReturnLength);
    typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(ULONG SystemInformationClass,PVOID SystemInformation,ULONG SystemInformationLength,PULONG ReturnLength);
    typedef NTSTATUS(NTAPI* fpNtQueryInformationThread)(HANDLE ThreadHandle,THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
    typedef NTSTATUS(NTAPI* fpNtPrivilegeCheck)(HANDLE ClientToken, PPRIVILEGE_SET RequiredPrivileges, PBOOLEAN Result);
    typedef NTSTATUS(WINAPI* fpLdrQueryProcessModuleInformation)(PLDR_MODULE ModuleInformation,ULONG SizeOfModuleInformation,PULONG ReturnedSize);
    typedef NTSTATUS(NTAPI* fpNtOpenProcessToken)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);
    typedef NTSTATUS(NTAPI* fpNtQueryInformationToken)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength,PULONG ReturnLength);
    typedef NTSTATUS(WINAPI* fpNtQueryVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

	using TNtQueryInformationProcess = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    using fpGetNamedSecurityInfoW = DWORD(WINAPI*)(LPCWSTR, SE_OBJECT_TYPE, SECURITY_INFORMATION, PSID*, PSID*, PACL*, PACL*, PSECURITY_DESCRIPTOR*);
    using fpConvertSidToStringSidW = BOOL(WINAPI*)(PSID, LPTSTR*);
}


