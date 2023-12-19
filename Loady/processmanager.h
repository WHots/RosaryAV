#pragma once
#include <Windows.h>
#include <optional>

#include "procutils.h"




class ProcessTally
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


    std::vector<const wchar_t*> processPrivilegeTokens = 
    {
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


    ProcessTally(DWORD procId);


public:


    float GetThreatLevel() const 
    {
        return threatLevel;
    }

    bool IsAnalysisFinished() const 
    {
        return finishedAnal;
    }

    ~ProcessTally();

    static std::optional<ProcessTally> Create(DWORD procId);
};