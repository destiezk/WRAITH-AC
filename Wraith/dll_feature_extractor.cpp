#include "main.h"
#include "Discord.h"
#include "dll_feature_extractor.h"
#include "webhook_sender.h"
#include <set>

// Calculate Shannon entropy of data block (measures randomness/encryption)
float DllFeatureExtractor::CalculateEntropy(LPVOID data, DWORD size) {
    if (!data || size == 0) return 0.0f;

    int freq[256] = { 0 };
    BYTE* bytes = (BYTE*)data;

    // Count byte frequencies (sample first 10KB for performance)
    DWORD sampleSize = (size < 10000) ? size : 10000;
    for (DWORD i = 0; i < sampleSize; i++) {
        freq[bytes[i]]++;
    }

    // Calculate Shannon entropy
    float entropy = 0.0f;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            float p = (float)freq[i] / sampleSize;
            entropy -= p * log2f(p);
        }
    }

    return entropy;
}

// Convert relative virtual address (RVA) to file offset
DWORD RvaToFileOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD rva, LPVOID lpBase) {
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);

    // Search for section containing the RVA
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (rva >= section->VirtualAddress &&
            rva < section->VirtualAddress + section->SizeOfRawData) {
            return rva - section->VirtualAddress + section->PointerToRawData;
        }
    }

    // Not in any section, assume it's already a file offset
    return rva;
}

// Count suspicious API imports commonly used by cheats/malware
int DllFeatureExtractor::CountSuspiciousAPIs(LPVOID lpBase, PIMAGE_NT_HEADERS ntHeaders) {
    int suspiciousCount = 0;

    // APIs commonly used for memory manipulation, hooking, and process injection
    static const std::set<std::string> suspiciousAPIs = {
        "CreateRemoteThread",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "VirtualAllocEx",
        "VirtualProtectEx",
        "SetWindowsHookEx",
        "GetAsyncKeyState",
        "NtQuerySystemInformation",
        "NtSetInformationThread",
        "ZwQuerySystemInformation",
        "OpenProcess",
        "VirtualProtect",
        "VirtualAlloc",
        "LoadLibraryA",
        "LoadLibraryW",
        "GetProcAddress",
        "CreateToolhelp32Snapshot",
        "Process32First",
        "Process32Next",
        "Module32First",
        "Module32Next"
    };

    try {
        // Get import directory
        DWORD importRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (importRVA == 0) return 0;

        // Convert RVA to file offset
        DWORD importOffset = RvaToFileOffset(ntHeaders, importRVA, lpBase);
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)lpBase + importOffset);

        // Iterate through imported DLLs
        while (importDesc->Name != 0) {
            PIMAGE_THUNK_DATA thunk = nullptr;
            DWORD thunkRVA = 0;

            // Get import name table
            if (importDesc->OriginalFirstThunk) {
                thunkRVA = importDesc->OriginalFirstThunk;
            }
            else if (importDesc->FirstThunk) {
                thunkRVA = importDesc->FirstThunk;
            }

            if (thunkRVA != 0) {
                DWORD thunkOffset = RvaToFileOffset(ntHeaders, thunkRVA, lpBase);
                thunk = (PIMAGE_THUNK_DATA)((BYTE*)lpBase + thunkOffset);

                // Iterate through imported functions
                while (thunk && thunk->u1.AddressOfData != 0) {
                    // Check if import is by name (not ordinal)
                    if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        DWORD nameRVA = (DWORD)thunk->u1.AddressOfData;
                        DWORD nameOffset = RvaToFileOffset(ntHeaders, nameRVA, lpBase);

                        PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)lpBase + nameOffset);
                        std::string apiName = (char*)importByName->Name;

                        // Check if API is suspicious
                        if (suspiciousAPIs.find(apiName) != suspiciousAPIs.end()) {
                            suspiciousCount++;
                        }
                    }
                    thunk++;
                }
            }
            importDesc++;
        }
    }
    catch (...) {
        return 0;
    }

    return suspiciousCount;
}

// Extract all features from a DLL file
DllFeatures DllFeatureExtractor::ExtractFeatures(const std::string& dllPath) {
    DllFeatures features = {};

    // Open the DLL file
    HANDLE hFile = CreateFileA(dllPath.c_str(), GENERIC_READ,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return features;
    }

    // Get file size
    DWORD fileSize = GetFileSize(hFile, NULL);
    features.fileSize = static_cast<float>(fileSize);

    // Create file mapping
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return features;
    }

    // Map file into memory
    LPVOID lpBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!lpBase) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return features;
    }

    try {
        // Parse DOS header
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpBase;

        if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
            // Parse NT headers
            PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + dosHeader->e_lfanew);

            if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
                // Extract basic PE information
                features.numSections = static_cast<float>(ntHeaders->FileHeader.NumberOfSections);
                features.entryPointRVA = static_cast<float>(ntHeaders->OptionalHeader.AddressOfEntryPoint);
                features.imageBase = static_cast<float>(ntHeaders->OptionalHeader.ImageBase);

                // Check for debug info and thread local storage
                features.hasDebugInfo = (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size > 0) ? 1.0f : 0.0f;
                features.hasTLS = (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0) ? 1.0f : 0.0f;

                // Count imported DLLs
                DWORD importRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                if (importRVA != 0) {
                    DWORD importOffset = RvaToFileOffset(ntHeaders, importRVA, lpBase);
                    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)lpBase + importOffset);
                    while (importDesc->Name != 0) {
                        features.numImports += 1.0f;
                        importDesc++;
                    }
                }

                // Count exported functions
                DWORD exportRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                if (exportRVA != 0) {
                    DWORD exportOffset = RvaToFileOffset(ntHeaders, exportRVA, lpBase);
                    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)lpBase + exportOffset);
                    features.numExports = static_cast<float>(exportDir->NumberOfFunctions);
                }

                // Count suspicious API imports
                features.suspiciousAPICount = static_cast<float>(CountSuspiciousAPIs(lpBase, ntHeaders));

                // Calculate file entropy
                features.entropy = CalculateEntropy(lpBase, fileSize);
            }
        }
    }
    catch (...) {
        // Return partial features on error
    }

    // Clean up
    UnmapViewOfFile(lpBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return features;
}
