#pragma once
#include <Windows.h>
#include <iostream>
#include <sddl.h>
#include <tchar.h>
#include <TlHelp32.h>

#include "strutils.h"
#include "memutils.h"
#include "ntdll.h"
#include "pointers.hpp"







struct ModuleInfo 
{
    DWORD baseAddress;
    DWORD size;
};


struct ProcessGenericInfo
{
    bool sectionFound;
    PVOID sectionAddress;
    SIZE_T sectionSize;
    PVOID mainModuleAddress;
    SIZE_T mainModuleSize;
};



template <typename T>
inline T DynamicImport(const wchar_t* module, const char* method)
{
    return reinterpret_cast<T>(GetProcAddress(GetModuleHandleW(module), method));
}




/// <summary>
/// Get address of a given function inside a specified module.
/// </summary>
/// <param name="moduleHandle">Module handle to search.</param>
/// <param name="method">Method name to find.</param>
/// <returns>Function address, otherwise nullptr.</returns>
FARPROC GetFunctionAddressW(HMODULE moduleHandle, const wchar_t* method);
/// <summary>
/// Retrieves the Process Environment Block (PEB) for the specified process.
/// </summary>
/// <param name="hProcess">Handle to the process.</param>
/// <returns>Pointer to the PEB of the process, otherwise nullptr.</returns>
inline PEB* PebBaseAddress(HANDLE hProcess);
/// <summary>
/// Retrieves the heap address for the specified process.
/// </summary>
/// <param name="hProcess">Handle to the process.</param>
/// <returns>Address to the process heap, otherwise nullptr.</returns>
PVOID GetProcessHeapAddress(HANDLE hProcess);
/// <summary>
/// Gets the count of handles of a specified type within a given process.
/// </summary>
/// <param name="pid">Process identifier.</param>
/// <param name="type">Handle type to count.</param>
/// <returns>Number of handles of the specified type, otherwise -1 in case of an error.</returns>
int GetHandleCount(DWORD pid, int type);
/// <summary>
/// Retrieves the Security Identifier (SID) of the user that owns a particular process.
/// </summary>
/// <param name="hProcess">Handle to the process.</param>
/// <returns>Pointer to a string that represents the SID, otherwise nullptr if failure.</returns>
LPTSTR GetProcessSid(HANDLE hProcess);
/// <summary>
/// Checks for the presence of a specified privilege within an access token.
/// </summary>
/// <param name="hToken">Handle to the access token.</param>
/// <param name="privilegeType">The name of the privilege to check.</param>
/// <returns>1 if the privilege is present, 0 if not, and -1 in case of an error.</returns>
int IsTokenPresent(HANDLE hToken, const wchar_t* privilegeType);
/// <summary>
/// Retrieves detailed information about the main module of a given process.
/// </summary>
/// <param name="hProcess">Handle to the process.</param>
/// <returns>A ModuleInfo structure containing the base address and size of the main module, with zeros in case of error.</returns>
ModuleInfo MainModuleInfoEx(HANDLE hProcess);
/// <summary>
/// Determines whether a thread was started in a suspended state.
/// </summary>
/// <param name="hThread">Handle to the thread.</param>
/// <returns>1 if the thread was started suspended, 0 if not, and -1 in case of an error.</returns>
int ThreadStartedSuspended(HANDLE hThread);
/// <summary>
/// Assesses the state of the main thread of a process, particularly if it was started suspended.
/// </summary>
/// <param name="pid">Process identifier of the target process.</param>
/// <returns>State of the main thread, with 1 indicating suspended, 0 if not, and -1 in case of an error.</returns>
int GetMainThreadState(DWORD pid);
/// <summary>
/// Queries and retrieves information about a specific memory section from a remote process.
/// </summary>
/// <param name="section">The name of the memory section to be queried.</param>
/// <param name="hProcess">Handle to the process.</param>
/// <returns>A ProcessGenericInfo structure with details about the memory section, or default values in case of error.</returns>
ProcessGenericInfo ProcessInfoQueryGeneric(const wchar_t* section, HANDLE hProcess);
