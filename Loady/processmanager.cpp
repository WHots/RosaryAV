#include "processmanager.h"






ProcessTally::ProcessTally(DWORD procId) : pid(procId), threatLevel(0.0f), finishedAnal(false)
{

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (!hProcess)    
        return;
    

    /*ProcessGenericInfo baseInformation = processutils::ProcessInfoQueryGeneric(L".text", hProcess);
    threatLevel += baseInformation.sectionFound ? -1.25 : 2.5;*/

    threatLevel += (processutils::MainThreadStartedSuspended(pid) == 1) ? 7.5 : -5.25;

    HANDLE hToken{};
    
    auto adjustThreatLevel = [](int result, float pass, float fail) -> float
    {
        switch (result)
        {
            case 0:  return fail;
            case 1:  return pass;
            default: return 0.0;
        }
    };

    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        for (const auto& privilege : processPrivilegeTokens)
            threatLevel += adjustThreatLevel(processutils::IsTokenPresent(hToken, privilege), 2.5, -2.0);

        CloseHandle(hToken);
    }

    std::vector<std::pair<std::wstring, int>> handleTypeCounts{};

    handleTypeCounts.emplace_back(std::make_pair(L"Process", processutils::GetHandleCount(pid, 0)));
    handleTypeCounts.emplace_back(std::make_pair(L"Device", processutils::GetHandleCount(pid, 3)));
    handleTypeCounts.emplace_back(std::make_pair(L"RegistryKey", processutils::GetHandleCount(pid, 17)));

    for (const auto& handleTypeCount : handleTypeCounts)
    {
        if (handleTypeCount.first == L"Process")
        {
            threatLevel += (handleTypeCount.second >= 1.25) ? handleTypeCount.second : 0.0f;
        }
        else if (handleTypeCount.first == L"Device")
            threatLevel += (handleTypeCount.second >= 5) ? handleTypeCount.second : 0.0f;
        else if (handleTypeCount.first == L"RegistryKey")
            threatLevel += (handleTypeCount.second >= 1) ? handleTypeCount.second : 0.0f;
    }

    int hiddenThreadCount = processutils::GetHiddenThreadCount(pid);
    threatLevel += (hiddenThreadCount > 0) ? hiddenThreadCount * 2.25 : -5.0;

    int dataWrittenMb = processutils::GetIoCounts(hProcess);
    threatLevel += (dataWrittenMb >= 1) ? hiddenThreadCount * 1.75 : -5.0;

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