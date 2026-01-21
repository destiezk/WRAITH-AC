// dll_detector.cpp - Runtime DLL detection with AI analysis
#include "main.h"
#include "ai_dll_detector.h"
#include "Discord.h"
#include "webhook_sender.h"
#include "utils.h"
#include "memory_scanner.h"

#pragma comment(lib, "Psapi.lib")

#include <Psapi.h>
#include <iostream>

namespace fs = std::filesystem;
using namespace std;

extern bool RPC(int uniqueID, BitStream* bitStream, PacketPriority priority,
    PacketReliability reliability, char orderingChannel, bool shiftTimestamp);
extern std::string WideToString(const wchar_t* wstr);
extern std::string GetHWID();


MemoryScanner g_memScanner;

// ============================
// CONSOLE LOGGING
// ============================

// Create debug console window for logging
static void InitializeConsole() {
    AllocConsole();

    FILE* fDummy;
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    freopen_s(&fDummy, "CONOUT$", "w", stderr);
    freopen_s(&fDummy, "CONIN$", "r", stdin);

    SetConsoleTitleA("Anti-Cheat AI - Debug Console");

    std::cout << "========================================" << std::endl;
    std::cout << "   ANTI-CHEAT AI - DEBUG CONSOLE       " << std::endl;
    std::cout << "========================================" << std::endl;
}

// ============================
// LOADLIBRARY HOOK SYSTEM WITH AI
// ============================

#define RPC_NEW_DLL_DETECTED 655910

// Function pointer types for hooked functions
typedef HMODULE(WINAPI* tLoadLibraryA)(LPCSTR);
typedef HMODULE(WINAPI* tLoadLibraryW)(LPCWSTR);
typedef HMODULE(WINAPI* tLoadLibraryExA)(LPCSTR, HANDLE, DWORD);
typedef HMODULE(WINAPI* tLoadLibraryExW)(LPCWSTR, HANDLE, DWORD);

// Original function pointers
static tLoadLibraryA oLoadLibraryA = nullptr;
static tLoadLibraryW oLoadLibraryW = nullptr;
static tLoadLibraryExA oLoadLibraryExA = nullptr;
static tLoadLibraryExW oLoadLibraryExW = nullptr;

// Thread-safe tracking of seen DLLs
static std::mutex g_seenMutex;
static std::unordered_set<std::string> g_seenDlls;

// Global AI detector instance
static std::unique_ptr<AIDllDetector> g_aiDetector;

// Check if path is in system directories (safe)
static bool IsSafePath(const std::string& fullPath) {
    std::string lower = fullPath;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (lower.find("\\windows\\") != std::string::npos) return true;
    if (lower.find("\\system32\\") != std::string::npos) return true;
    if (lower.find("\\syswow64\\") != std::string::npos) return true;
    if (lower.find("\\winsxs\\") != std::string::npos) return true;
    if (lower.find("\\program files\\") != std::string::npos) return true;
    if (lower.find("\\program files (x86)\\") != std::string::npos) return true;

    return false;
}

// Check if file is the game executable
static bool IsGameExecutable(const std::string& fullPath) {
    std::string lower = fullPath;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (lower.find("gta_sa.exe") != std::string::npos) return true;
    if (lower.find("samp.exe") != std::string::npos) return true;

    return false;
}

// Whitelist of known legitimate game DLLs
static bool IsKnownGameDll(const std::string& dllNameLower) {
    if (dllNameLower.find("samp") != std::string::npos) return true;
    if (dllNameLower.find("bass") != std::string::npos) return true;
    if (dllNameLower.find("vorbis") != std::string::npos) return true;
    if (dllNameLower.find("ogg") != std::string::npos) return true;
    if (dllNameLower.find("eax") != std::string::npos) return true;
    if (dllNameLower.find("modloader") != std::string::npos) return true;
    if (dllNameLower.find("wraith-ac") != std::string::npos) return true;
    if (dllNameLower.find("onnxruntime") != std::string::npos) return true;
    if (dllNameLower.find("std.") != std::string::npos) return true;

    return false;
}

// Send DLL features to webhook for logging/analysis
static void SendDllFeaturesToWebhook(const std::string& dllPath) {
    DllFeatureExtractor extractor;
    DllFeatures features = extractor.ExtractFeatures(dllPath);

    // Extract filename only
    size_t lastSlash = dllPath.find_last_of("\\/");
    std::string dllName = (lastSlash != std::string::npos) ? dllPath.substr(lastSlash + 1) : dllPath;

    // Format imageBase in scientific notation
    char imageBaseStr[32];
    sprintf_s(imageBaseStr, "%.5e", features.imageBase);

    // Format entropy with precision
    char entropyStr[32];
    sprintf_s(entropyStr, "%.5g", features.entropy);

    // Build feature structure message
    std::string FASZ = "{\n";
    FASZ += "    \"" + dllName + "\"\",\n";

    std::string structFormat;
    structFormat += "    " + std::to_string((int)features.fileSize) + ".0f,\n";
    structFormat += "    " + std::to_string((int)features.numSections) + ".0f,\n";
    structFormat += "    " + std::to_string((int)features.numImports) + ".0f,\n";
    structFormat += "    " + std::to_string((int)features.numExports) + ".0f,\n";
    structFormat += "    " + std::to_string((int)features.entryPointRVA) + ".0f,\n";
    structFormat += "    " + std::string(imageBaseStr) + "f,\n";
    structFormat += "    " + std::to_string((int)features.hasDebugInfo) + ".0f,\n";
    structFormat += "    " + std::to_string((int)features.hasTLS) + ".0f,\n";
    structFormat += "    " + std::to_string((int)features.suspiciousAPICount) + ".0f,\n";
    structFormat += "    " + std::string(entropyStr) + ",\n";
    structFormat += "    0.01f\n";
    structFormat += "},";

    // Send messages to webhook
    SendWebhookAsync2(FASZ.c_str());
    Sleep(100);
    SendWebhookAsync2(structFormat.c_str());
}

// Scan modules already loaded before anti-cheat started
void ScanAlreadyLoadedModules() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "  SCANNING PRE-LOADED MODULES (AI)...  " << std::endl;
    std::cout << "========================================\n" << std::endl;

    HANDLE hProcess = GetCurrentProcess();
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            wchar_t szModName[MAX_PATH];

            if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                std::wstring modPath(szModName);

                try {
                    std::filesystem::path p(modPath);
                    std::wstring modName = p.filename().wstring();
                    std::string modNameStr = WideToString(modName.c_str());
                    std::string modPathStr = WideToString(modPath.c_str());

                    std::string modPathLower = modPathStr;
                    std::transform(modPathLower.begin(), modPathLower.end(), modPathLower.begin(), ::tolower);

                    // Skip game executable
                    if (IsGameExecutable(modPathLower)) {
                        std::cout << "[OK - GAME EXE] " << modNameStr << std::endl;
                        continue;
                    }

                    // Skip system paths
                    if (IsSafePath(modPathLower)) {
                        std::cout << "[OK - SAFE PATH] " << modNameStr << std::endl;
                        continue;
                    }

                    // Check if in game directory
                    char exePath[MAX_PATH];
                    GetModuleFileNameA(NULL, exePath, MAX_PATH);
                    std::string exeDir(exePath);
                    exeDir = exeDir.substr(0, exeDir.find_last_of("\\/"));
                    std::transform(exeDir.begin(), exeDir.end(), exeDir.begin(), ::tolower);

                    if (modPathLower.find(exeDir) != std::string::npos) {
                        std::string modNameLower = modNameStr;
                        std::transform(modNameLower.begin(), modNameLower.end(), modNameLower.begin(), ::tolower);

                        // Check whitelist
                        if (IsKnownGameDll(modNameLower)) {
                            std::cout << "[OK - GAME FILE] " << modNameStr << std::endl;
                            continue;
                        }

                        std::cout << "[CHECKING AI] Unknown game folder DLL: " << modNameStr << std::endl;
                    }

                    // Run AI detection
                    if (g_aiDetector && g_aiDetector->IsSuspicious(modPathStr)) {
                        float confidence = g_aiDetector->GetLastConfidence();

                        std::cout << "\n*** [AI BLOCKED] ***" << std::endl;
                        std::cout << "DLL: " << modNameStr << std::endl;
                        std::cout << "Path: " << modPathStr << std::endl;
                        std::cout << "Confidence: " << (confidence * 100.0f) << "%\n" << std::endl;

                        std::string msg = "Wraith AI detected suspicious DLL!\n\n";
                        msg += "DLL: " + modNameStr + "\n";

                        std::string pcName = GetComputerName();
                        std::string hwid = GetHWID();

                        // Send to webhook
                        SendDllFeaturesToWebhook(modNameStr);
                        SendWebhookAsync("**" + GetPlayerName() + " (" + hwid + ")" + "** has loaded a suspicious dll before Wraith-AC, terminating game.\n**DLL:** `" + modNameStr.c_str() + "` | **Path:** `" + modPathStr.c_str() + "` | **Confidence:** `" + std::to_string((int)(confidence * 100)) + "%`");

                        // Delayed termination
                        std::thread([]() {
                            Sleep(5000);
                            TerminateProcess(GetCurrentProcess(), 1);
                            }).detach();

                        SetForegroundWindow(GetDesktopWindow());
                        MessageBoxA(NULL, msg.c_str(), "Wraith AI - Detection", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_SETFOREGROUND);
                        return;
                    }

                    std::cout << "[AI OK] " << modNameStr << std::endl;
                }
                catch (...) {
                    continue;
                }
            }
        }
    }

    std::cout << "\n[OK] Pre-loaded module scan complete. No suspicious DLLs found.\n" << std::endl;
}

// Extract filename from ANSI path
static std::string FilenameFromAnsiPath(const char* pathA) {
    if (!pathA) return std::string();
    try {
        fs::path p(pathA);
        return p.filename().string();
    }
    catch (...) {
        return std::string(pathA);
    }
}

// Extract filename from wide path
static std::string FilenameFromWidePath(const wchar_t* pathW) {
    if (!pathW) return std::string();
    try {
        std::string utf = WideToString(pathW);
        fs::path p(utf);
        return p.filename().string();
    }
    catch (...) {
        return WideToString(pathW);
    }
}

// Get full path from ANSI string
static std::string GetFullPathFromAnsi(const char* pathA) {
    if (!pathA) return std::string();
    return std::string(pathA);
}

// Get full path from wide string
static std::string GetFullPathFromWide(const wchar_t* pathW) {
    if (!pathW) return std::string();
    return WideToString(pathW);
}

// Check if RPC is available
static bool CanSendRPC() {
    return (dwSAMPAddr != 0 && oRPC != nullptr);
}

// Send DLL name to server via RPC
static void SendDllNameToServer_Safe(const std::string& dllName) {
    try {
        if (!CanSendRPC()) return;

        size_t len = dllName.size();
        if (len == 0 || len >= 256) return;

        BitStream bsSend;
        uint32_t nameLen = static_cast<uint32_t>(len);
        bsSend.Write<uint32_t>(nameLen);
        bsSend.Write(dllName.c_str(), nameLen);
        RPC(RPC_NEW_DLL_DETECTED, &bsSend, HIGH_PRIORITY, RELIABLE_SEQUENCED, NULL, false);
        bsSend.ResetWritePointer();
    }
    catch (...) {}
}

// Track if DLL has been seen before (prevents duplicate processing)
static bool MarkDllSeenIfNew(const std::string& filename) {
    std::string lower = filename;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    std::lock_guard<std::mutex> lock(g_seenMutex);
    if (g_seenDlls.find(lower) != g_seenDlls.end()) return false;
    g_seenDlls.insert(lower);
    return true;
}

// Terminate process when suspicious DLL detected
static void TerminateOnIllegalDll(const std::string& dllName, const std::string& fullPath, float aiConfidence) {
    std::cout << "\n*** [TERMINATING] ***" << std::endl;
    std::cout << "DLL: " << dllName << std::endl;
    std::cout << "AI Confidence: " << (aiConfidence * 100.0f) << "%" << std::endl;

    SendDetectionToDiscord(dllName, fullPath, aiConfidence);
    SendDllFeaturesToWebhook(fullPath);

    std::string message = "Wraith AI detected suspicious DLL!\n\n";
    message += "The game will now close.";

    MessageBoxA(NULL, message.c_str(), "Wraith AI - Detection", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_TOPMOST);
    SendDllNameToServer_Safe(dllName);

    // Delayed termination thread
    std::thread([]() {
        Sleep(5000);
        TerminateProcess(GetCurrentProcess(), 1);
        }).detach();

    SetForegroundWindow(GetDesktopWindow());
    MessageBoxA(NULL, message.c_str(), "Wraith AI - Detection", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_SETFOREGROUND);
}

// Hooked LoadLibraryA - intercepts DLL loads
HMODULE WINAPI hkLoadLibraryA(LPCSTR lpLibFileName) {
    if (lpLibFileName) {
        try {
            std::string filename = FilenameFromAnsiPath(lpLibFileName);
            std::string fullPath = GetFullPathFromAnsi(lpLibFileName);

            if (!filename.empty()) {
                std::cout << "[HOOK] LoadLibraryA: " << filename << std::endl;

                std::string fullPathLower = fullPath;
                std::transform(fullPathLower.begin(), fullPathLower.end(), fullPathLower.begin(), ::tolower);

                // Allow game executable
                if (IsGameExecutable(fullPathLower)) {
                    std::cout << "  -> Game executable, allowing" << std::endl;
                    return oLoadLibraryA ? oLoadLibraryA(lpLibFileName) : LoadLibraryA(lpLibFileName);
                }

                // Allow safe paths
                if (IsSafePath(fullPath)) {
                    std::cout << "  -> Safe path, allowing" << std::endl;
                    return oLoadLibraryA ? oLoadLibraryA(lpLibFileName) : LoadLibraryA(lpLibFileName);
                }

                // Check whitelist
                std::string filenameLower = filename;
                std::transform(filenameLower.begin(), filenameLower.end(), filenameLower.begin(), ::tolower);

                if (IsKnownGameDll(filenameLower)) {
                    std::cout << "  -> Known game DLL, allowing" << std::endl;
                    return oLoadLibraryA ? oLoadLibraryA(lpLibFileName) : LoadLibraryA(lpLibFileName);
                }

                // Check with AI
                std::cout << "  -> Checking with AI..." << std::endl;

                if (g_aiDetector && g_aiDetector->IsSuspicious(fullPath)) {
                    if (MarkDllSeenIfNew(filename)) {
                        float confidence = g_aiDetector->GetLastConfidence();
                        std::cout << "  -> AI DETECTED SUSPICIOUS! Confidence: " << (confidence * 100.0f) << "%" << std::endl;
                        TerminateOnIllegalDll(filename, fullPath, confidence);
                    }
                    SetLastError(ERROR_ACCESS_DENIED);
                    return NULL;
                }

                std::cout << "  -> AI says OK" << std::endl;
            }
        }
        catch (...) {
            std::cout << "[ERROR] Exception in LoadLibraryA hook!" << std::endl;
            MessageBoxA(NULL, "Exception in LoadLibraryA hook!", "Anti-Cheat Error", MB_OK | MB_ICONERROR);
            TerminateProcess(GetCurrentProcess(), 1);
        }
    }
    return oLoadLibraryA ? oLoadLibraryA(lpLibFileName) : LoadLibraryA(lpLibFileName);
}

// Hooked LoadLibraryW - wide character version
HMODULE WINAPI hkLoadLibraryW(LPCWSTR lpLibFileName) {
    if (lpLibFileName) {
        try {
            std::string filename = FilenameFromWidePath(lpLibFileName);
            std::string fullPath = GetFullPathFromWide(lpLibFileName);

            if (!filename.empty()) {
                std::cout << "[HOOK] LoadLibraryW: " << filename << std::endl;

                std::string fullPathLower = fullPath;
                std::transform(fullPathLower.begin(), fullPathLower.end(), fullPathLower.begin(), ::tolower);

                if (IsGameExecutable(fullPathLower)) {
                    std::cout << "  -> Game executable, allowing" << std::endl;
                    return oLoadLibraryW ? oLoadLibraryW(lpLibFileName) : LoadLibraryW(lpLibFileName);
                }

                if (IsSafePath(fullPath)) {
                    std::cout << "  -> Safe path, allowing" << std::endl;
                    return oLoadLibraryW ? oLoadLibraryW(lpLibFileName) : LoadLibraryW(lpLibFileName);
                }

                std::string filenameLower = filename;
                std::transform(filenameLower.begin(), filenameLower.end(), filenameLower.begin(), ::tolower);

                if (IsKnownGameDll(filenameLower)) {
                    std::cout << "  -> Known game DLL, allowing" << std::endl;
                    return oLoadLibraryW ? oLoadLibraryW(lpLibFileName) : LoadLibraryW(lpLibFileName);
                }

                std::cout << "  -> Checking with AI..." << std::endl;

                if (g_aiDetector && g_aiDetector->IsSuspicious(fullPath)) {
                    if (MarkDllSeenIfNew(filename)) {
                        float confidence = g_aiDetector->GetLastConfidence();
                        std::cout << "  -> AI DETECTED SUSPICIOUS! Confidence: " << (confidence * 100.0f) << "%" << std::endl;
                        TerminateOnIllegalDll(filename, fullPath, confidence);
                    }
                    SetLastError(ERROR_ACCESS_DENIED);
                    return NULL;
                }

                std::cout << "  -> AI says OK" << std::endl;
            }
        }
        catch (...) {
            std::cout << "[ERROR] Exception in LoadLibraryW hook!" << std::endl;
            MessageBoxA(NULL, "Exception in LoadLibraryW hook!", "Anti-Cheat Error", MB_OK | MB_ICONERROR);
            TerminateProcess(GetCurrentProcess(), 1);
        }
    }
    return oLoadLibraryW ? oLoadLibraryW(lpLibFileName) : LoadLibraryW(lpLibFileName);
}

// Hooked LoadLibraryExA - extended version
HMODULE WINAPI hkLoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    if (lpLibFileName) {
        try {
            std::string filename = FilenameFromAnsiPath(lpLibFileName);
            std::string fullPath = GetFullPathFromAnsi(lpLibFileName);

            if (!filename.empty()) {
                std::cout << "[HOOK] LoadLibraryExA: " << filename << std::endl;

                std::string fullPathLower = fullPath;
                std::transform(fullPathLower.begin(), fullPathLower.end(), fullPathLower.begin(), ::tolower);

                if (IsGameExecutable(fullPathLower)) {
                    return oLoadLibraryExA ? oLoadLibraryExA(lpLibFileName, hFile, dwFlags)
                        : LoadLibraryExA(lpLibFileName, hFile, dwFlags);
                }

                if (IsSafePath(fullPath)) {
                    return oLoadLibraryExA ? oLoadLibraryExA(lpLibFileName, hFile, dwFlags)
                        : LoadLibraryExA(lpLibFileName, hFile, dwFlags);
                }

                std::string filenameLower = filename;
                std::transform(filenameLower.begin(), filenameLower.end(), filenameLower.begin(), ::tolower);

                if (IsKnownGameDll(filenameLower)) {
                    return oLoadLibraryExA ? oLoadLibraryExA(lpLibFileName, hFile, dwFlags)
                        : LoadLibraryExA(lpLibFileName, hFile, dwFlags);
                }

                if (g_aiDetector && g_aiDetector->IsSuspicious(fullPath)) {
                    if (MarkDllSeenIfNew(filename)) {
                        float confidence = g_aiDetector->GetLastConfidence();
                        TerminateOnIllegalDll(filename, fullPath, confidence);
                    }
                    SetLastError(ERROR_ACCESS_DENIED);
                    return NULL;
                }
            }
        }
        catch (...) {
            MessageBoxA(NULL, "Exception in LoadLibraryExA hook!", "Anti-Cheat Error", MB_OK | MB_ICONERROR);
            TerminateProcess(GetCurrentProcess(), 1);
        }
    }
    return oLoadLibraryExA ? oLoadLibraryExA(lpLibFileName, hFile, dwFlags)
        : LoadLibraryExA(lpLibFileName, hFile, dwFlags);
}

// Hooked LoadLibraryExW - extended wide character version
HMODULE WINAPI hkLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    if (lpLibFileName) {
        try {
            std::string filename = FilenameFromWidePath(lpLibFileName);
            std::string fullPath = GetFullPathFromWide(lpLibFileName);

            if (!filename.empty()) {
                std::cout << "[HOOK] LoadLibraryExW: " << filename << std::endl;

                std::string fullPathLower = fullPath;
                std::transform(fullPathLower.begin(), fullPathLower.end(), fullPathLower.begin(), ::tolower);

                if (IsGameExecutable(fullPathLower)) {
                    return oLoadLibraryExW ? oLoadLibraryExW(lpLibFileName, hFile, dwFlags)
                        : LoadLibraryExW(lpLibFileName, hFile, dwFlags);
                }

                if (IsSafePath(fullPath)) {
                    return oLoadLibraryExW ? oLoadLibraryExW(lpLibFileName, hFile, dwFlags)
                        : LoadLibraryExW(lpLibFileName, hFile, dwFlags);
                }

                std::string filenameLower = filename;
                std::transform(filenameLower.begin(), filenameLower.end(), filenameLower.begin(), ::tolower);

                if (IsKnownGameDll(filenameLower)) {
                    return oLoadLibraryExW ? oLoadLibraryExW(lpLibFileName, hFile, dwFlags)
                        : LoadLibraryExW(lpLibFileName, hFile, dwFlags);
                }

                if (g_aiDetector && g_aiDetector->IsSuspicious(fullPath)) {
                    if (MarkDllSeenIfNew(filename)) {
                        float confidence = g_aiDetector->GetLastConfidence();
                        TerminateOnIllegalDll(filename, fullPath, confidence);
                    }
                    SetLastError(ERROR_ACCESS_DENIED);
                    return NULL;
                }
            }
        }
        catch (...) {
            MessageBoxA(NULL, "Exception in LoadLibraryExW hook!", "Anti-Cheat Error", MB_OK | MB_ICONERROR);
            TerminateProcess(GetCurrentProcess(), 1);
        }
    }
    return oLoadLibraryExW ? oLoadLibraryExW(lpLibFileName, hFile, dwFlags)
        : LoadLibraryExW(lpLibFileName, hFile, dwFlags);
}

// Install hooks on all LoadLibrary variants
void InstallLoadLibraryHooks() {
    std::cout << "\n[INIT] Installing LoadLibrary hooks..." << std::endl;

    MH_CreateHookApi(L"kernel32", "LoadLibraryA", &hkLoadLibraryA,
        reinterpret_cast<void**>(&oLoadLibraryA));
    MH_CreateHookApi(L"kernel32", "LoadLibraryW", &hkLoadLibraryW,
        reinterpret_cast<void**>(&oLoadLibraryW));
    MH_CreateHookApi(L"kernel32", "LoadLibraryExA", &hkLoadLibraryExA,
        reinterpret_cast<void**>(&oLoadLibraryExA));
    MH_CreateHookApi(L"kernel32", "LoadLibraryExW", &hkLoadLibraryExW,
        reinterpret_cast<void**>(&oLoadLibraryExW));

    MH_EnableHook(&LoadLibraryA);
    MH_EnableHook(&LoadLibraryW);
    MH_EnableHook(&LoadLibraryExA);
    MH_EnableHook(&LoadLibraryExW);

    std::cout << "[INIT] Hooks installed successfully!" << std::endl;
}

// Initialize anti-cheat system
void StartLoadLibraryDetectionAndWorker() {
    InitializeConsole();
    std::cout << "\n[INIT] Starting Anti-Cheat AI..." << std::endl;

    g_aiDetector = std::make_unique<AIDllDetector>();

    // Load AI model
    if (!g_aiDetector->InitializeFromResource()) {
        std::cout << "[ERROR] Failed to initialize AI model!" << std::endl;
        MessageBoxA(NULL,
            "Failed to initialize Wraith-AI model!\n"
            "Quitting.",
            "Anti-Cheat Warning", MB_OK | MB_ICONWARNING);
        g_aiDetector.reset();
        TerminateProcess(GetCurrentProcess(), 1);
    }
    else {
        std::cout << "[INIT] AI model initialized successfully!" << std::endl;
    }

    // Scan pre-loaded modules
    ScanAlreadyLoadedModules();

    // Install hooks
    InstallLoadLibraryHooks();

    g_memScanner.TakeSnapshot();  // Take snapshot of current memory
    g_memScanner.StartMonitoring();  // Start checking for new regions

    std::cout << "\n[READY] Anti-Cheat AI is now active!\n" << std::endl;
}

// Shutdown anti-cheat system
void StopLoadLibraryDetectionAndWorker() {
    std::cout << "\n[SHUTDOWN] Stopping Anti-Cheat..." << std::endl;

    // Disable hooks
    MH_DisableHook(&LoadLibraryA);
    MH_DisableHook(&LoadLibraryW);
    MH_DisableHook(&LoadLibraryExA);
    MH_DisableHook(&LoadLibraryExW);

    // Clear tracked DLLs
    std::lock_guard<std::mutex> lock(g_seenMutex);
    g_seenDlls.clear();

    // Destroy AI detector
    g_aiDetector.reset();

    std::cout << "[SHUTDOWN] Anti-Cheat stopped" << std::endl;
}
