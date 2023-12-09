// #include <iostream>
//#include "processmanager.h"

#include "procutils.h"

int main()
{    
   
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, 4220);
    std::cout << processutils::GetIoCounts(hProcess) << std::endl;
    //std::optional<ProcessTally> managerOpt = ProcessTally::Create(17836);

    //if (managerOpt.has_value()) 
    //{
    //    // Access the ProcessManager object.
    //    ProcessTally manager = managerOpt.value();

    //    // Check the threat level.
    //    float threatLevel = manager.GetThreatLevel();

    //    // Check if the analysis is finished.
    //    bool analysisFinished = manager.IsAnalysisFinished();

    //    // Print the results.
    //    std::cout << "Threat Level: " << threatLevel << std::endl;
    //    std::cout << "Analysis Finished: " << (analysisFinished ? "Yes" : "No") << std::endl;
    //}
    //else
    //{
    //    printf("fails");
    //}
}
