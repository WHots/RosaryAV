#include "processmanager.h"






ProcessManager::ProcessManager(DWORD procId) : pid(procId), threatLevel(0.0f), finishedAnal(false)
{

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (!hProcess)
        return;


    ProcessGenericInfo baseInformation = ProcessInfoQueryGeneric(L".text", hProcess);
    threatLevel += baseInformation.sectionFound ? -1.25 : 2.5;

    threatLevel += (GetMainThreadState(pid) == 1) ? 2.5 : -1.25;

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
        return;


    auto adjustThreatLevel = [](int result, float pass, float fail) -> float
    {
        switch (result)
        {
        case 0:  return fail;
        case 1:  return pass;
        default: return 0.0;
        }
    };

    for (const auto& privilege : privileges)
        threatLevel += adjustThreatLevel(IsTokenPresent(hToken, privilege), 2.0, -1.50);

    CloseHandle(hToken);

    //  Max score up to this point = 33f.

    std::vector<std::pair<std::wstring, int>> handleTypeCounts;

    //  Refer to ntdll.h for handle types.
    handleTypeCounts.emplace_back(std::make_pair(L"Process", GetHandleCount(pid, 0)));
    handleTypeCounts.emplace_back(std::make_pair(L"Device", GetHandleCount(pid, 3)));
    handleTypeCounts.emplace_back(std::make_pair(L"RegistryKey", GetHandleCount(pid, 17)));

    for (const auto& handleTypeCount : handleTypeCounts)
    {
        if (handleTypeCount.first == L"Process")
        {
            threatLevel += (handleTypeCount.second >= 3) ? handleTypeCount.second : 0.0f;
        }
        else if (handleTypeCount.first == L"Device")
            threatLevel += (handleTypeCount.second >= 1) ? handleTypeCount.second : 0.0f;
        else if (handleTypeCount.first == L"RegistryKey")
            threatLevel += (handleTypeCount.second >= 3) ? handleTypeCount.second : 0.0f;
    }

    finishedAnal = true;
    threatLevel = (threatLevel > 100.0f) ? 100.0f : threatLevel;
}


std::optional<ProcessManager> ProcessManager::Create(DWORD procId)
{
    ProcessManager manager(procId);

    if (!manager.hProcess)
        return std::nullopt;

    return manager;
}


ProcessManager::~ProcessManager()
{
    if (hProcess)
        CloseHandle(hProcess);
}