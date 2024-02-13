//  #include <iostream>
//  #include "processmanager.h"
//  #include "procutils.h"
//  #include "processmanager.h"

//#include <iostream>
//#include "processmanager.h"
#include "processfiltermanager.h"


int main() {


    /*DWORD procId = GetCurrentProcessId();

    std::optional<ProcessTally> processTally = ProcessTally::Create(procId);

    if (processTally.has_value()) 
    {
        double threatLevel = processTally->threatLevel;
        bool finishedAnalysis = processTally->finishedAnal;

        std::cout << "Threat level of process " << procId << ": " << threatLevel << std::endl;
        std::cout << "Analysis finished: " << std::boolalpha << finishedAnalysis << std::endl;

    }
    else {
        std::cerr << "Failed to create ProcessTally for process " << procId << std::endl;
    }*/

    ProcessFilterManager manager;
    std::vector<DWORD> matchingProcesses = manager.getProcessesMatchingSID();

    for (DWORD pid : matchingProcesses) {
        std::cout << "Matching Process ID: " << pid << std::endl;
    }

    return 0;
}
