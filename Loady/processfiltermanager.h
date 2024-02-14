#pragma once 
#include <Windows.h>
#include <vector>
#include <iostream>
#include <memory>
#include <TlHelp32.h>
#include "procutils.h"





class ProcessFilterManager
{

    LPTSTR currentProcessSID;
    /// <summary>
    /// Retrieves the SID of the specified process.
    /// </summary>
    /// <param name="processId">The process ID for which to retrieve the SID.</param>
    /// <returns>The SID of the specified process, or nullptr if an error occurred.</returns>
    inline LPTSTR _GetProcessSid(const DWORD processId);

public:
    /// <summary>
    /// Constructs a new ProcessFilterManager object and initializes the SID of the current process.
    /// </summary>
    ProcessFilterManager(); 
    /// <summary>
    /// Retrieves a list of process IDs whose SIDs match the SID of the current process.
    /// </summary>
    /// <returns>A vector containing the process IDs of the processes matching the SID of the current process.</returns>
    std::vector<DWORD> getProcessesMatchingSID();
};
