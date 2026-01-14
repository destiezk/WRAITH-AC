// dll_feature_extractor.h
#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cmath>

struct DllFeatures {
    float fileSize;
    float numSections;
    float numImports;
    float numExports;
    float entryPointRVA;
    float imageBase;
    float hasDebugInfo;
    float hasTLS;
    float suspiciousAPICount;
    float entropy;
};

class DllFeatureExtractor {
public:
    static DllFeatures ExtractFeatures(const std::string& dllPath);

private:
    static float CalculateEntropy(LPVOID data, DWORD size);
    static int CountSuspiciousAPIs(LPVOID lpBase, PIMAGE_NT_HEADERS ntHeaders);
};
