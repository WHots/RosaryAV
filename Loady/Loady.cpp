//#include "memutils.h"
#include <iostream>
#include "memorymanager.hpp"
#include <vector>
#include "fileutils.h"











int main() {

    UniqueHandle<HANDLE> hProcess(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, 1164));

    if (hProcess.IsValid()) 
    {    
        std::wstring executablePath;

        if (fileutils::GetExecutablePathName(hProcess.Get(), executablePath)) 
        {
            std::wcout << "Executable Path: " << executablePath << std::endl;
        }
        else 
        {
            std::cerr << "Failed to get executable path" << std::endl;
        }
    }
}

    

    ///*ProcessFilterManager filterManager{};
    //std::vector<DWORD> matchingProcesses = filterManager.GetProcessesMatchingFilter();

    //ThreadManager launcher{};

    //for (const auto& pid : matchingProcesses) 
    //{
    //    launcher.addTask([pid](DWORD processId) {
    //        ProcessAnalyzer analyzer(processId);
    //        auto [result, errorCode] = analyzer.AnalyzeProcess();

    //    }, pid); 
    //}

    //launcher.LaunchAll();
    //launcher.JoinAll();

    //return 0;*/
