#pragma once
#include <windows.h>
#include <iostream>
#include <variant> 
#include <string>
#include "processtallymanager.hpp"







class ProcessAnalyzer 
{

    DWORD pid;


public:

    enum class AnalysisErrorCode 
    {
        Success = 1,
        ProcessTallyFail = -1,
        // ... 
    };

    struct AnalysisResult 
    {
        double threatLevel;
        bool finishedAnal;
    };

    struct AnalysisError 
    {
        int message;
    };

    ProcessAnalyzer(DWORD procId) : pid(procId) {}

    std::pair<AnalysisResult, AnalysisErrorCode> AnalyzeProcess();
};