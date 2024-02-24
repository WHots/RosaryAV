#pragma once
#include <Windows.h>
#include <iostream>
#include <sddl.h>
#include <tchar.h>
#include <TlHelp32.h> 
#include <functional>

#include "strutils.h"
#include "importmanager.h"
#include "ntexapi.h"
#include "ntmmapi.h"
#include "ntpsapi.h"
#include "prototypes.hpp"





namespace processutils
{

    struct SectionInfo 
    {
        std::string name;
        DWORD virtualAddress;
        DWORD sizeOfRawData;
    };


    enum class ObjectType : ULONG
    {
        Process = 0,
        Thread = 1,
        File = 2,
        Device = 3,
        Event = 4,
        Mutex = 5,
        Semaphore = 6,
        Timer = 7,
        Port = 8,
        Key = 9,
        Section = 10,
        Job = 11,
        ProcessGroup = 12,
        Directory = 13,
        SymbolicLink = 14,
        Pipe = 15,
        WaitablePort = 16,
        RegistryKey = 17,
        RegistryValue = 18,
        Win32Driver = 19,
        Win32Service = 20,
        Win32Device = 21,
        Win32Process = 22,
        Win32Thread = 23,
        Win32Event = 24,
        Win32Mutex = 25,
        Win32Semaphore = 26,
        Win32Timer = 27,
        Win32Port = 28,
        Win32Key = 29,
        Win32Section = 30,
        Win32Job = 31,
        Win32ProcessGroup = 32,
        Win32Directory = 33,
        Win32SymbolicLink = 34,
        Win32Pipe = 35,
        Win32WaitablePort = 36,
        Win32RegistryKey = 37,
        Win32RegistryValue = 38,
    };


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
    inline int ThreadStartedSuspended(HANDLE hThread);
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
    /// Enables or disables a specified privilege in the access token of the current process. 
    /// </summary>
    /// <param name="privilegeName">The name of the privilege to adjust.</param>
    /// <param name="enable">True to enable the privilege, False to disable it.</param>
    /// <returns>True if the operation was successful, False otherwise.</returns>
    bool SetTokenPrivilege(const char* privilegeName, bool enable);
    /// <summary>
    /// Enumerates the section headers of a process and returns detailed information about them.
    /// </summary>
    /// <param name="hProcess">Handle to the process whose sections will be enumerated.</param>
    /// <returns>A vector of SectionInfo structures, each containing the name, virtual address, and size of a section. If no sections are found or an error occurs, returns an empty vector.</returns>
    std::vector<SectionInfo> GetSectionInfo(const HANDLE hProcess, const char* sectionName);
    /// <summary>
    /// Attempts to retrieve the process signer information.
    /// </summary>
    /// <param name="hProcess">Handle to the process.</param>
    /// <returns>A UCHAR value representing the process signer (extracted from the protection level), or -1 in case of errors.</returns>
    UCHAR GetProcessSigner(const HANDLE hProcess);

}
