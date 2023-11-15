#pragma once
#include <windows.h>
#include "procutils.h"
#include <optional>




const wchar_t* privileges[] = {

    SE_CREATE_TOKEN_NAME,
    SE_ASSIGNPRIMARYTOKEN_NAME,
    SE_LOCK_MEMORY_NAME,
    SE_DEBUG_NAME,
    SE_TCB_NAME,
    SE_LOAD_DRIVER_NAME,
    SE_IMPERSONATE_NAME,
    SE_INCREASE_QUOTA_NAME,
    SE_SHUTDOWN_NAME,
    SE_TAKE_OWNERSHIP_NAME,
    SE_CREATE_PERMANENT_NAME,
    SE_CHANGE_NOTIFY_NAME,
    SE_ENABLE_DELEGATION_NAME,
    SE_MANAGE_VOLUME_NAME
};



class ProcessManager
{
    /// <summary>
    /// Target process ID.
    /// </summary>
    DWORD pid;
    /// <summary>
    /// Generic handle to target process.
    /// </summary>
    HANDLE hProcess;
    /// <summary>
    /// Complete target process threat level.
    /// </summary>
    float threatLevel;
    /// <summary>
    /// Indicates if the anal process has ran to completion or not.
    /// </summary>
    bool finishedAnal;

    ProcessManager(DWORD procId);


public:

    /// <summary>
    /// Destruco
    /// </summary>
    ~ProcessManager();

    static std::optional<ProcessManager> Create(DWORD procId);
};