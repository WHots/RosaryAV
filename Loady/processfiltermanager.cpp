#include "processfiltermanager.hpp"






ProcessFilterManager::ProcessFilterManager() {
    currentProcessSID = processutils::GetProcessSid(GetCurrentProcess());
}


std::vector<DWORD> ProcessFilterManager::GetProcessesMatchingFilter()
{

    std::vector<DWORD> matchingProcesses{};
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe32{};
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32))
        {
            do {

                if (pe32.th32ProcessID == GetCurrentProcessId())
                    continue;

                LPTSTR processSID = _GetProcessSid(pe32.th32ProcessID);

                if (processSID != nullptr && lstrcmp(currentProcessSID, processSID) == 0)
                    matchingProcesses.emplace_back(pe32.th32ProcessID);

                if (processSID != nullptr)
                    LocalFree(processSID);

            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return matchingProcesses;
}


inline LPTSTR ProcessFilterManager::_GetProcessSid(const DWORD processId)
{

    LPTSTR sidString = nullptr;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);

    if (hProcess)
    {
        sidString = processutils::GetProcessSid(hProcess);
        CloseHandle(hProcess);
    }
    else
        return nullptr;

    return sidString;
}
