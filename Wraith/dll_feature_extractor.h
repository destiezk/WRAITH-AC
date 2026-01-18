// dll_feature_extractor.h - Extract features from DLL files for analysis
#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cmath>

// Feature vector representing DLL characteristics
struct DllFeatures {
    float fileSize;            // Size of DLL file in bytes
    float numSections;         // Number of PE sections
    float numImports;          // Number of imported functions
    float numExports;          // Number of exported functions
    float entryPointRVA;       // Relative virtual address of entry point
    float imageBase;           // Preferred base address
    float hasDebugInfo;        // 1.0 if debug info present, 0.0 otherwise
    float hasTLS;              // 1.0 if thread local storage present, 0.0 otherwise
    float suspiciousAPICount;  // Count of potentially suspicious API calls
    float entropy;             // Shannon entropy (measures randomness/encryption)
};

class DllFeatureExtractor {
public:
    // Extract all features from a DLL file
    static DllFeatures ExtractFeatures(const std::string& dllPath);

private:
    // Calculate Shannon entropy of data block
    static float CalculateEntropy(LPVOID data, DWORD size);

    // Count suspicious API imports (e.g., VirtualAlloc, WriteProcessMemory)
    static int CountSuspiciousAPIs(LPVOID lpBase, PIMAGE_NT_HEADERS ntHeaders);
};
