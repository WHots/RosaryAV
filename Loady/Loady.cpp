//  #include <iostream>
//  #include "processmanager.h"

#include "procutils.h"

int main()
{    
   

    HANDLE hProcess = GetCurrentProcess();
    PIMAGE_SECTION_HEADER textSection = nullptr;

    
    LPTSTR sidString = processutils::GetProcessSid(hProcess);
    if (!sidString) {
        std::cerr << "Failed to get process SID: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // Print the SID string
    wprintf(L"%s\n", sidString);

    // Free the allocated memory
    LocalFree(sidString);

    // Close the process handle
    CloseHandle(hProcess);

    return 1;

    /*if (processutils::GetSection(hProcess, ".text", &textSection)) 
    {
        printf("Virtual address: 0x%p\n", textSection->VirtualAddress);
        printf("Virtual size: %d bytes\n", textSection->Misc.VirtualSize);
    }*/
    
    
    /*std::optional<ProcessTally> managerOpt = ProcessTally::Create(GetCurrentProcessId());

    if (managerOpt.has_value()) 
    {
        ProcessTally manager = managerOpt.value();

        float threatLevel = manager.GetThreatLevel();

        bool analysisFinished = manager.IsAnalysisFinished();

        std::cout << "Threat Level: " << threatLevel << std::endl;
        std::cout << "Analysis Finished: " << (analysisFinished ? "Yes" : "No") << std::endl;
    }
    else
    {
        printf("fails");
    }*/
}
