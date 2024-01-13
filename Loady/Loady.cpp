//  #include <iostream>
//  #include "processmanager.h"
//#include "procutils.h"
#include "processmanager.h"



int main()
{    
   
    //  tesetssstst

    std::optional<ProcessTally> managerOpt = ProcessTally::Create(GetCurrentProcessId());

<<<<<<< HEAD
    if (managerOpt.has_value())
=======
    
    LPTSTR sidString = processutils::GetProcessSid(hProcess);
    if (!sidString) {
        std::cerr << "Failed to get process SID: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }


    wprintf(L"%s\n", sidString);


    LocalFree(sidString);

    CloseHandle(hProcess);

    return 1;

    /*if (processutils::GetSection(hProcess, ".text", &textSection)) 
    {
        printf("Virtual address: 0x%p\n", textSection->VirtualAddress);
        printf("Virtual size: %d bytes\n", textSection->Misc.VirtualSize);
    }*/
    
    
    /*std::optional<ProcessTally> managerOpt = ProcessTally::Create(GetCurrentProcessId());

    if (managerOpt.has_value()) 
>>>>>>> 57be8ce40755930e69d4d8bb3c58b3d1331dd244
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
    }
}
