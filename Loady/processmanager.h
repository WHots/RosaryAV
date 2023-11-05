#pragma once
#include <windows.h>
#include "procutils.h"



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
    private:
        DWORD pid;
        HANDLE hProcess;
        float threatLevel;

        //  ProcessGenericInfo ProcessBaseInformation(HANDLE hProcess, const wchar_t* section);

    public:
        ProcessManager(DWORD procId);
        ~ProcessManager();
};
