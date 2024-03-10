#include "rosary.hpp"












std::pair<ProcessAnalyzer::AnalysisResult, ProcessAnalyzer::AnalysisErrorCode> ProcessAnalyzer::AnalyzeProcess() 
{

    AnalysisResult result{};

    std::optional<ProcessTally> processTally = ProcessTally::Create(this->pid);

    if (processTally.has_value()) 
    {       
        result.threatLevel = processTally->threatLevel;
        std::cout << result.threatLevel<< " -> PID: " << pid << std::endl;
        result.finishedAnal = processTally->finishedAnal;
        return std::make_pair(result, AnalysisErrorCode::Success);
    }
    else    
        return std::make_pair(AnalysisResult{}, AnalysisErrorCode::ProcessTallyFail);
}