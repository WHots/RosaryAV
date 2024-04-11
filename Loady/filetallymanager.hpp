#pragma once
#include <Windows.h>
#include <string>











class FileTally 
{

    double getEntropy() const { return entropy; }


public:

    FileTally(const std::string& filePath);
 
    void calculateEntropy();

    double entropy;
};
