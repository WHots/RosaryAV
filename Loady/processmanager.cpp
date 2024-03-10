#include "processmanager.hpp"






ProcessTally::ProcessTally(DWORD procId) : pid(procId), threatLevel(0.0), finishedAnal(false)
{  

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (!hProcess)
        return;
    

    threatLevel += (processutils::GetOldestThreadStartFlag(pid) == 1) ? 4.0 : -4.0;


    HANDLE hToken{};
      
    if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        for (const auto& privilege : processPrivilegeTokens)
            threatLevel += (processutils::IsTokenPresent(hToken, privilege) == 1) ? 2.5 : -1.5;

        CloseHandle(hToken);
    }


    //  std::vector<processutils::SectionInfo> sectionInfo{};
    //  sectionInfo = processutils::GetSectionInfo(hProcess, ".text");

    //  threatLevel += (sectionInfo.empty()) ? -2.50 : 3.0;


    std::vector<std::pair<std::wstring, int>> handleTypeCounts{};

    handleTypeCounts.emplace_back(std::make_pair(L"Process", processutils::GetCurrentHandleCount(pid, 0)));
    handleTypeCounts.emplace_back(std::make_pair(L"Device", processutils::GetCurrentHandleCount(pid, 3)));
    handleTypeCounts.emplace_back(std::make_pair(L"RegistryKey", processutils::GetCurrentHandleCount(pid, 17)));

    for (const auto& handleTypeCount : handleTypeCounts)
    {
        if (handleTypeCount.first == L"Process")
        {
            threatLevel += (handleTypeCount.second >= 3) ? handleTypeCount.second : -1.0;
        }
        else if (handleTypeCount.first == L"Device")        
            threatLevel += (handleTypeCount.second >= 5) ? handleTypeCount.second : -2.0;

        else if (handleTypeCount.first == L"RegistryKey")
            threatLevel += (handleTypeCount.second >= 2) ? handleTypeCount.second / 1.75 : -2.5;        
    }


    int hiddenThreadCount = processutils::GetHiddenThreadCount(pid);
    threatLevel += (hiddenThreadCount > 0) ? hiddenThreadCount * 2.25 : -2.0;

    int dataWrittenMb = processutils::GetWriteCount(hProcess);
    threatLevel += (dataWrittenMb >= 1) ? 2.25 : -2.75;

    finishedAnal = true;
    threatLevel = (threatLevel > 100.0) ? 100.0 : threatLevel;
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
    //
}