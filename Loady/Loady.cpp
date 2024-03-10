#include "rosary.hpp"
#include "threadmanager.hpp"
#include "processfiltermanager.hpp"













int main() 
{

    ProcessFilterManager filterManager{};
    std::vector<DWORD> matchingProcesses = filterManager.GetProcessesMatchingFilter();

    ThreadManager launcher;

    for (const auto& pid : matchingProcesses) {
        launcher.addTask([pid](DWORD processId) {
            ProcessAnalyzer analyzer(processId);
            auto [result, errorCode] = analyzer.AnalyzeProcess();

            }, pid); 
    }

    launcher.LaunchAll();
    launcher.JoinAll();

    // tests ...

    

    return 0;
}