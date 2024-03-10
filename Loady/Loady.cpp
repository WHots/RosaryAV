#include "rosary.hpp"
#include "threadmanager.hpp"
#include "processfiltermanager.hpp"













int main() 
{

    //  DWORD pid = GetCurrentProcessId();
    ProcessFilterManager filterManager{};
    std::vector<DWORD> matchingProcesses = filterManager.GetProcessesMatchingFilter();

    ThreadManager launcher;

    for (const auto& pid : matchingProcesses) {
        launcher.addTask([pid](DWORD processId) { // Lambda with explicit parameter
            ProcessAnalyzer analyzer(processId);
            auto [result, errorCode] = analyzer.AnalyzeProcess();
            // ... Handle the result ...
            }, pid); // Pass pid to the Task constructor 
    }

    // Launch all the analysis tasks
    launcher.LaunchAll();

    // Wait for all analysis tasks to complete
    launcher.JoinAll();


    

    return 0;
}