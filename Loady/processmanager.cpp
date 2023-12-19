#include "processmanager.h"






ProcessTally::ProcessTally(DWORD procId) : pid(procId), threatLevel(0.0f), finishedAnal(false)
{

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (!hProcess)
        return;
    

    threatLevel += (processutils::GetOldestThreadStartFlag(pid) == 1) ? 4.0 : -4.0;


    HANDLE hToken{};
      
    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        for (const auto& privilege : processPrivilegeTokens)
            threatLevel += (processutils::IsTokenPresent(hToken, privilege) == 1) ? 2.5f : -2.0f;

        CloseHandle(hToken);
    }


    PIMAGE_SECTION_HEADER header = nullptr; //  ...
    threatLevel += (processutils::GetSectionHeader(hProcess, ".text", &header) == 1) ? -2.50 : 2.50;


    std::vector<std::pair<std::wstring, int>> handleTypeCounts{};

    handleTypeCounts.emplace_back(std::make_pair(L"Process", processutils::GetCurrentHandleCount(pid, 0)));
    handleTypeCounts.emplace_back(std::make_pair(L"Device", processutils::GetCurrentHandleCount(pid, 3)));
    handleTypeCounts.emplace_back(std::make_pair(L"RegistryKey", processutils::GetCurrentHandleCount(pid, 17)));

    for (const auto& handleTypeCount : handleTypeCounts)
    {
        if (handleTypeCount.first == L"Process")
        {
            threatLevel += (handleTypeCount.second >= 3) ? handleTypeCount.second : -2.0f;
        }
        else if (handleTypeCount.first == L"Device")        
            threatLevel += (handleTypeCount.second >= 5) ? handleTypeCount.second : -5.0f;

        else if (handleTypeCount.first == L"RegistryKey")
            threatLevel += (handleTypeCount.second >= 2) ? handleTypeCount.second / 1.75 : -2.5f;        
    }


    int hiddenThreadCount = processutils::GetHiddenThreadCount(pid);
    threatLevel += (hiddenThreadCount > 0) ? hiddenThreadCount * 2.25 : -3.0;

    int dataWrittenMb = processutils::GetWriteCount(hProcess);
    threatLevel += (dataWrittenMb >= 1) ? 2.25 : -2.75;

    finishedAnal = true;
    threatLevel = (threatLevel > 100.0f) ? 100.0f : threatLevel;
}


std::optional<ProcessTally> ProcessTally::Create(DWORD procId)
{
    ProcessTally manager(procId);

    if (!manager.hProcess)           
        return std::nullopt;
    

    return manager;
}



ProcessTally::~ProcessTally()
{
    if (hProcess)
        CloseHandle(hProcess);
}