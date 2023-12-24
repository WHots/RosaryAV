#pragma once
#include <Windows.h>
#include <iostream>
#include <sddl.h>
#include <tchar.h>
#include <TlHelp32.h> 
#include <functional>

#include "strutils.h"
#include "importmanager.h"
#include "ntdll.h"
#include "prototypes.hpp"





namespace processutils
{

    /// <summary>
    /// Retrieves the Process Environment Block (PEB) for the specified process.
    /// </summary>
    /// <param name="hProcess">Handle to the process.</param>
    /// <returns>Pointer to the PEB of the process, otherwise nullptr.</returns>
    static inline PEB* PebBaseAddressEx(const HANDLE hProcess);
    /// <summary>
    /// Retrieves the heap address for the specified process.
    /// </summary>
    /// <param name="hProcess">Handle to the process.</param>
    /// <returns>Address to the process heap, otherwise nullptr.</returns>
    PVOID GetProcessHeapAddress(const HANDLE hProcess);
    /// <summary>
    /// Gets the count of handles of a specified type within a given process.
    /// </summary>
    /// <param name="pid">Process identifier.</param>
    /// <param name="type">Handle type to count.</param>
    /// <returns>Number of handles of the specified type, otherwise -1 in case of an error.</returns>
    int GetCurrentHandleCount(const int pid, const int type);
    /// <summary>
    /// Retrieves the Security Identifier (SID) of the user that owns a particular process.
    /// </summary>
    /// <param name="hProcess">Handle to the process.</param>
    /// <returns>Pointer to a string that represents the SID, otherwise nullptr if failure.</returns>
    LPTSTR GetProcessSid(const HANDLE hProcess);
    /// <summary>
    /// Checks for the presence of a specified privilege within an access token.
    /// </summary>
    /// <param name="hToken">Handle to the access token.</param>
    /// <param name="privilegeType">The name of the privilege to check.</param>
    /// <returns>1 if the privilege is present, 0 if not, and -1 in case of an error.</returns>
    int IsTokenPresent(const HANDLE hToken, const wchar_t* privilegeType);
    /// <summary>
    /// Determines whether a thread was started in a suspended state.
    /// </summary>
    /// <param name="hThread">Handle to the thread.</param>
    /// <returns>1 if the thread was started suspended, 0 if not, and -1 in case of an error.</returns>
    static inline int ThreadStartedSuspended(HANDLE hThread);
    /// <summary>
    /// Assesses the state of the main thread of a process, particularly if it was started suspended.
    /// </summary>
    /// <param name="pid">Process identifier of the target process.</param>
    /// <returns>State of the main thread, with 1 indicating suspended, 0 if not, and -1 in case of an error.</returns>
    int GetOldestThreadStartFlag(const int pid);
    /// <summary>
    /// Retrieves the count of hidden threads within a specified process.
    /// </summary>
    /// <param name="pid">The process ID for which hidden threads are to be counted.</param>
    /// <returns>The number of hidden threads within the specified process.</returns>
    int GetHiddenThreadCount(const int pid);
    /// <summary>
    /// Retrieves the count of write operations performed by a specified process.
    /// </summary>
    /// <param name="hProcess">A handle to the target process.</param>
    /// <returns>
    /// The number of write operations performed by the specified process.
    /// If the operation is successful, the count is returned; otherwise, -1 is returned.
    /// </returns>
    int GetWriteCount(const HANDLE hProcess);
    /// <summary>
    /// Attempts to locate a specific section header within a process's memory space.
    /// </summary>
    /// <param name="hProcess">Handle to the process whose memory will be searched.</param>
    /// <param name="sectionName">The name of the section to be found.</param>
    /// <param name="sectionHeader">Pointer to a variable that will hold the address of the found section header if successful, or nullptr otherwise.</param>
    /// <returns>
    /// - 1 if the specified section was successfully found.
    /// - 0 if the section was not found or an error occurred.
    /// - -1 if an invalid process handle was provided.
    /// </returns>
    int GetSectionHeader(const HANDLE hProcess, const char* sectionName, PIMAGE_SECTION_HEADER* targetSection);
}
