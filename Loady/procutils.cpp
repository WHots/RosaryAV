#include "procutils.h"







FARPROC GetFunctionAddressW(HMODULE moduleHandle, const wchar_t* method)
{

    if (!moduleHandle)       
        return nullptr;
    

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleHandle;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)moduleHandle + dosHeader->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)moduleHandle + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    if (importDescriptor != NULL)
    {
        while (importDescriptor->Name != 0)
        {
            const char* importedModuleName = (const char*)((DWORD_PTR)moduleHandle + importDescriptor->Name);

            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)moduleHandle + importDescriptor->OriginalFirstThunk);

            while (thunk && thunk->u1.Function)
            {
                if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
                {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)moduleHandle + thunk->u1.AddressOfData);
                    char* importedFunctionName = (char*)importByName->Name;
                    wchar_t* wideImportedFunctionName = stringutil::CharToWChar_T(importedFunctionName);                    

                    if (WIDESTRING_COMPARE(method, wideImportedFunctionName) == 0)
                    {                       
                        DWORD_PTR functionRVA = ntHeaders->OptionalHeader.ImageBase + (DWORD_PTR)thunk->u1.Function;     
                        delete[] wideImportedFunctionName;
                        return (FARPROC)functionRVA;
                    }   

                    delete[] wideImportedFunctionName;
                }
                thunk++;
            }
            importDescriptor++;
        }
    }

    return nullptr;
}


PEB* PebBaseAddress(DWORD pid)
{

    PROCESS_BASIC_INFORMATION pbi{};
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);

    if (hProcess == INVALID_HANDLE_VALUE)
        return nullptr;

    auto ptrNtQueryInformationProcess = (pointers::TNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");

    return (ptrNtQueryInformationProcess)
        ? ((CloseHandle(hProcess), (ptrNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr) == 0)) ? pbi.PebBaseAddress : nullptr)
        : nullptr;


    // ...
}


int GetHandleCount(DWORD pid, int type) 
{

    PSYSTEM_HANDLE_INFORMATION buffer{};
    ULONG bufferSize = 0xffffff;
    buffer = (PSYSTEM_HANDLE_INFORMATION)malloc(bufferSize);
    NTSTATUS status;

    auto NtQuerySystemInformation = pointers::_NtQuerySystemInformation(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    status = NtQuerySystemInformation(0x10, buffer, bufferSize, NULL);

    if (!NT_SUCCESS(status))
    {
        free(buffer);
        return -1;
    }

    const PVOID ProcAddress = nullptr;
    int count = 0;

    for (ULONG i = 0; i <= buffer->HandleCount; i++) 
    {
        if ((buffer->Handles[i].ProcessId == pid)) 
        {
            if (buffer->Handles[i].ObjectTypeNumber == type)
                count += 1;
        }

    }
    free(buffer);
    return count;
}


LPTSTR GetProcessSid(DWORD pid) 
{

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

    if (!hProcess) 
        return nullptr;
    

    HANDLE hToken = nullptr;
    LPTSTR sidString = nullptr;

    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        DWORD dwSize = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);

        if (dwSize > 0) 
        {
            PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);

            if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) 
            {
                PSID pSid = pTokenUser->User.Sid;

                if (ConvertSidToStringSidW(pSid, &sidString)) 
                {
                    free(pTokenUser);
                    CloseHandle(hToken);
                    CloseHandle(hProcess);
                    return sidString;
                }
            }

            free(pTokenUser);
        }

        CloseHandle(hToken);
    }

    CloseHandle(hProcess);
    return nullptr;
}


int IsTokenPresent(HANDLE hToken)
{

    int fail = -1;
    NTSTATUS status;

    auto NtPrivilegeCheck = pointers::fpNtPrivilegeCheck(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtPrivilegeCheck"));

    if (!NtPrivilegeCheck)
        return fail;

    LUID luid;

    if(!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid))
        return fail;

    PRIVILEGE_SET requiredPrivileges{};
    requiredPrivileges.PrivilegeCount = 1;
    requiredPrivileges.Control = PRIVILEGE_SET_ALL_NECESSARY;

    LUID_AND_ATTRIBUTES privilegeArray[1];
    privilegeArray[0].Luid = luid;
    privilegeArray[0].Attributes = SE_PRIVILEGE_ENABLED;

    requiredPrivileges.Privilege[0] = privilegeArray[0];

    BOOLEAN hasPrivilege;
    status = NtPrivilegeCheck(hToken, &requiredPrivileges, &hasPrivilege);

    return (NT_SUCCESS(status) && hasPrivilege) ? 1 : 0;
}


ModuleInfo MainModuleEx(DWORD processID) 
{

    ModuleInfo mainModuleInfo = { 0 };

    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

    if (processHandle == NULL)        
        return mainModuleInfo;


    HMODULE modules[1];
    DWORD bytesNeeded;

    if (EnumProcessModules(processHandle, modules, sizeof(modules), &bytesNeeded)) 
    {
        int moduleCount = bytesNeeded / sizeof(HMODULE);
        TCHAR moduleName[MAX_PATH];

        for (int i = 0; i < moduleCount; i++) 
        {
            if (GetModuleFileNameEx(processHandle, modules[i], moduleName, MAX_PATH)) 
            {
                if (_tcsstr(moduleName, TEXT(".exe"))) 
                {
                    MODULEINFO moduleInfo;

                    if (GetModuleInformation(processHandle, modules[i], &moduleInfo, sizeof(moduleInfo))) 
                    {
                        mainModuleInfo.baseAddress = (DWORD)moduleInfo.lpBaseOfDll;
                        mainModuleInfo.size = moduleInfo.SizeOfImage;
                        break;
                    }
                }
            }
        }
    }

    CloseHandle(processHandle);
    return mainModuleInfo;
}