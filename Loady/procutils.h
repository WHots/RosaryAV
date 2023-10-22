#pragma once
#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <sddl.h>
#include <tchar.h>

#include "strutils.h"
#include "memutils.h"
#include "ntdll.h"
#include "pointers.hpp"





struct ModuleInfo 
{
    DWORD baseAddress;
    DWORD size;
};



std::vector<std::wstring> tokenPrivileges = 
{
        SE_CREATE_TOKEN_NAME,
        SE_ASSIGNPRIMARYTOKEN_NAME,
        SE_LOCK_MEMORY_NAME,
        SE_INCREASE_QUOTA_NAME,
        SE_UNSOLICITED_INPUT_NAME,
        SE_MACHINE_ACCOUNT_NAME,
        SE_TCB_NAME,
        SE_SECURITY_NAME,
        SE_TAKE_OWNERSHIP_NAME,
        SE_LOAD_DRIVER_NAME,
        SE_SYSTEM_PROFILE_NAME,
        SE_SYSTEMTIME_NAME,
        SE_PROF_SINGLE_PROCESS_NAME,
        SE_INC_BASE_PRIORITY_NAME,
        SE_CREATE_PAGEFILE_NAME,
        SE_CREATE_PERMANENT_NAME
};


/// <summary>
/// Get address of a given function inside a specified module.
/// </summary>
/// <param name="moduleHandle">Module name to search.</param>
/// <param name="method">Method name.</param>
/// <returns>Function address, otherwise nullptr.</returns>
FARPROC GetFunctionAddressW(HMODULE moduleHandle, const wchar_t* method);
/// <summary>
/// Returns pointer to PEB base address.
/// </summary>
/// <returns>Pointer to PEB base address, otherwise nullptr.</returns>
PEB* PebBaseAddress();
/// <summary>
/// Get count of particular handle type.
/// </summary>
/// <param name="pid">Process ID.</param>
/// <param name="type">Handle type.</param>
/// <returns>Returns count of opened specified handle type, otherwise -1.</returns>
/// <remarks>
/// For more information on handle types, see <see cref="ntdll.h\ObjectType"/>.
/// </remarks>
int GetHandleCount(DWORD pid, int type);
/// <summary>
/// Get the Security Identifier (SID) of the user associated with a specified process.
/// </summary>
/// <param name="pid">Process ID of the target process.</param>
/// <returns>Returns the SID of the user owning the specified process. Returns nullptr in case of failure.</returns>
/// <remarks>
/// This function retrieves the SID of the user who owns the specified process. It uses Windows API functions to open the process, 
/// extract the user's SID, and then converts the SID to a string representation.
/// </remarks>
LPTSTR GetProcessSid(DWORD pid);
/// <summary>
/// Check if a specific privilege is enabled for the given token.
/// </summary>
/// <param name="hToken">Handle to the token to be checked.</param>
/// <returns>Returns 1 if the privilege is enabled, 0 if it's disabled, and -1 in case of failure.</returns>
/// <remarks>
/// This function checks if a specified privilege is enabled for the provided token. It uses the NtPrivilegeCheck function
/// (from the ntdll.dll) to perform the privilege check. The function returns 1 if the privilege is enabled, 0 if it's not enabled,
/// and -1 if there's a failure during the process.
/// </remarks>
int IsTokenPresent(HANDLE hToken);
ModuleInfo MainModuleInfoEx(DWORD processID);
