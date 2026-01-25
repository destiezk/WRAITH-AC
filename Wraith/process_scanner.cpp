// Process scanner - Monitors running processes for suspicious activity
#include "main.h"
#include <TlHelp32.h>
#include <Psapi.h>
#include <sstream>
#include <vector>
#include <fstream>
#include <iostream>
#include "utils.h"
#include "Discord.h"
#include "webhook_sender.h"

extern std::string GetHWID();

typedef void (WINAPI* QFPIN)(HANDLE, DWORD, LPWSTR, PDWORD);

// Check if RPC system is ready
static bool CanSendRPC() {
    return (dwSAMPAddr != 0 && oRPC != nullptr);
}

// RPC identifier for suspicious process reports
#define RPC_SUSPICIOUS_PROCESS 655911

class CProcessScanner {
private:
    std::mutex scanMutex;
    bool isRunning;
    std::thread scanThread;
    std::unordered_set<std::wstring> whitelistedProcesses;  // Known safe processes
    std::unordered_set<std::wstring> scannedProcesses;      // Already checked this session
    bool consoleAllocated;

    // Populate whitelist with legitimate system and application processes
    void InitializeWhitelist() {
        // Windows System Processes
        whitelistedProcesses.insert(L"system");
        whitelistedProcesses.insert(L"system idle process");
        whitelistedProcesses.insert(L"smss.exe");
        whitelistedProcesses.insert(L"csrss.exe");
        whitelistedProcesses.insert(L"wininit.exe");
        whitelistedProcesses.insert(L"services.exe");
        whitelistedProcesses.insert(L"lsass.exe");
        whitelistedProcesses.insert(L"lsm.exe");
        whitelistedProcesses.insert(L"svchost.exe");
        whitelistedProcesses.insert(L"winlogon.exe");
        whitelistedProcesses.insert(L"explorer.exe");
        whitelistedProcesses.insert(L"dwm.exe");
        whitelistedProcesses.insert(L"taskhostw.exe");
        whitelistedProcesses.insert(L"taskhost.exe");
        whitelistedProcesses.insert(L"runtimebroker.exe");
        whitelistedProcesses.insert(L"dllhost.exe");
        whitelistedProcesses.insert(L"conhost.exe");
        whitelistedProcesses.insert(L"sihost.exe");
        whitelistedProcesses.insert(L"fontdrvhost.exe");
        whitelistedProcesses.insert(L"ctfmon.exe");
        whitelistedProcesses.insert(L"spoolsv.exe");
        whitelistedProcesses.insert(L"searchindexer.exe");
        whitelistedProcesses.insert(L"searchprotocolhost.exe");
        whitelistedProcesses.insert(L"searchfilterhost.exe");
        whitelistedProcesses.insert(L"audiodg.exe");
        whitelistedProcesses.insert(L"wudfhost.exe");
        whitelistedProcesses.insert(L"wmiprvse.exe");
        whitelistedProcesses.insert(L"taskmgr.exe");
        whitelistedProcesses.insert(L"smartscreen.exe");

        // Windows Defender
        whitelistedProcesses.insert(L"msmpeng.exe");
        whitelistedProcesses.insert(L"nissrv.exe");
        whitelistedProcesses.insert(L"securityhealthservice.exe");
        whitelistedProcesses.insert(L"securityhealthsystray.exe");
        whitelistedProcesses.insert(L"antimalwareservice.exe");

        // Windows Update
        whitelistedProcesses.insert(L"wuauclt.exe");
        whitelistedProcesses.insert(L"trustedinstaller.exe");

        // Common Browsers
        whitelistedProcesses.insert(L"chrome.exe");
        whitelistedProcesses.insert(L"firefox.exe");
        whitelistedProcesses.insert(L"msedge.exe");
        whitelistedProcesses.insert(L"opera.exe");
        whitelistedProcesses.insert(L"brave.exe");
        whitelistedProcesses.insert(L"nvoawrappercache.exe");

        // Communication Apps
        whitelistedProcesses.insert(L"discord.exe");
        whitelistedProcesses.insert(L"skype.exe");
        whitelistedProcesses.insert(L"teamspeak3.exe");
        whitelistedProcesses.insert(L"slack.exe");
        whitelistedProcesses.insert(L"telegram.exe");
        whitelistedProcesses.insert(L"medal.exe");

        // Media Players
        whitelistedProcesses.insert(L"spotify.exe");
        whitelistedProcesses.insert(L"vlc.exe");
        whitelistedProcesses.insert(L"musicbee.exe");

        // Gaming Platforms & Anti-Cheats
        whitelistedProcesses.insert(L"steam.exe");
        whitelistedProcesses.insert(L"steamwebhelper.exe");
        whitelistedProcesses.insert(L"epicgameslauncher.exe");
        whitelistedProcesses.insert(L"origin.exe");
        whitelistedProcesses.insert(L"battle.net.exe");
        whitelistedProcesses.insert(L"vgtray.exe");
        whitelistedProcesses.insert(L"vgc.exe");
        whitelistedProcesses.insert(L"valorant.exe");
        whitelistedProcesses.insert(L"valorant-win64-shipping.exe");
        whitelistedProcesses.insert(L"leagueclient.exe");
        whitelistedProcesses.insert(L"leagueclientux.exe");
        whitelistedProcesses.insert(L"oawrapper.exe");
        whitelistedProcesses.insert(L"discordsystemhelper.exe");

        // Other Anti-Cheat Systems
        whitelistedProcesses.insert(L"easyanticheat.exe");
        whitelistedProcesses.insert(L"battleye.exe");
        whitelistedProcesses.insert(L"bedaisy.sys");

        // Cloud Storage
        whitelistedProcesses.insert(L"onedrive.exe");
        whitelistedProcesses.insert(L"dropbox.exe");
        whitelistedProcesses.insert(L"googledrivesync.exe");
        whitelistedProcesses.insert(L"backup and sync.exe");

        // Development Tools
        whitelistedProcesses.insert(L"code.exe");
        whitelistedProcesses.insert(L"devenv.exe");

        // Game Executables
        whitelistedProcesses.insert(L"gta_sa.exe");
        whitelistedProcesses.insert(L"samp.exe");
    }

    // Log colored messages to console
    void LogToConsole(const std::string& message, const std::string& color = "") {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

        if (color == "RED") {
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
        }
        else if (color == "GREEN") {
            SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        }
        else if (color == "YELLOW") {
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        }
        else if (color == "CYAN") {
            SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        }
        else {
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }

        std::cout << message << std::endl;
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    // Check if process name is whitelisted
    bool IsWhitelistedProcess(const std::wstring& processName) {
        std::wstring lower = processName;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        return whitelistedProcesses.find(lower) != whitelistedProcesses.end();
    }

    // Check if process is in a legitimate system/program directory
    bool IsLegitimateLocation(const std::wstring& path) {
        std::wstring lower = path;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        // Windows System Directories
        if (lower.find(L"c:\\windows\\") != std::wstring::npos) return true;
        if (lower.find(L"\\windows\\system32\\") != std::wstring::npos) return true;
        if (lower.find(L"\\windows\\syswow64\\") != std::wstring::npos) return true;
        if (lower.find(L"\\windows\\winsxs\\") != std::wstring::npos) return true;

        // Program Files
        if (lower.find(L"\\program files\\") != std::wstring::npos) return true;
        if (lower.find(L"\\program files (x86)\\") != std::wstring::npos) return true;

        // Gaming Platforms
        if (lower.find(L"\\steam\\") != std::wstring::npos) return true;
        if (lower.find(L"\\steamapps\\") != std::wstring::npos) return true;
        if (lower.find(L"\\epic games\\") != std::wstring::npos) return true;
        if (lower.find(L"\\origin games\\") != std::wstring::npos) return true;
        if (lower.find(L"\\riot games\\") != std::wstring::npos) return true;

        // Common AppData Locations
        if (lower.find(L"\\appdata\\local\\discord\\") != std::wstring::npos) return true;
        if (lower.find(L"\\appdata\\local\\mozilla firefox\\") != std::wstring::npos) return true;
        if (lower.find(L"\\appdata\\local\\programs\\opera gx\\") != std::wstring::npos) return true;
        if (lower.find(L"\\appdata\\local\\programs\\opera\\") != std::wstring::npos) return true;
        if (lower.find(L"\\appdata\\local\\medal\\") != std::wstring::npos) return true;
        //C:\Users\Korisnik\AppData\Local\Medal\recorder - 3.1150.0\MedalEncoder.exe

        // Cloud Storage
        if (lower.find(L"\\microsoft\\onedrive\\") != std::wstring::npos) return true;
        if (lower.find(L"\\appdata\\local\\microsoft\\onedrive\\") != std::wstring::npos) return true;
        if (lower.find(L"\\dropbox\\") != std::wstring::npos) return true;
        if (lower.find(L"\\google\\drive\\") != std::wstring::npos) return true;

        return false;
    }

    // Check if process name contains suspicious keywords
    bool IsSuspiciousName(const std::wstring& processName) {
        std::wstring lower = processName;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        if (lower.find(L"cheat") != std::wstring::npos) return true;
        if (lower.find(L"hack") != std::wstring::npos) return true;
        if (lower.find(L"inject") != std::wstring::npos) return true;
        if (lower.find(L"trainer") != std::wstring::npos) return true;
        if (lower.find(L"bypass") != std::wstring::npos) return true;
        if (lower.find(L"crack") != std::wstring::npos) return true;

        return false;
    }

    // Enable debug privileges for process access
    void AdjustTokens(HANDLE process) {
        TOKEN_PRIVILEGES token_privileges;
        DWORD dwSize;
        ZeroMemory(&token_privileges, sizeof(token_privileges));

        if (process != NULL) {
            HANDLE hToken;
            if (OpenProcessToken(process, TOKEN_ALL_ACCESS, &hToken)) {
                LookupPrivilegeValue(NULL, SE_DEBUG_NAME,
                    &token_privileges.Privileges[0].Luid);
                token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                token_privileges.PrivilegeCount = 1;
                AdjustTokenPrivileges(hToken, FALSE, &token_privileges,
                    0, NULL, &dwSize);
                CloseHandle(hToken);
            }
        }
    }

    // Verify that process file exists on disk
    bool DoesFileExist(const std::wstring& path) {
        DWORD attrib = GetFileAttributesW(path.c_str());
        return (attrib != INVALID_FILE_ATTRIBUTES &&
            !(attrib & FILE_ATTRIBUTE_DIRECTORY));
    }

    // Send suspicious process report to server via RPC
    void ReportSuspiciousProcess(const std::wstring& path) {
        if (!CanSendRPC()) return;

        std::string pathStr = WideToString(path.c_str());

        BitStream bsSend;
        uint32_t len = static_cast<uint32_t>(pathStr.size());
        bsSend.Write<uint32_t>(len);
        bsSend.Write(pathStr.c_str(), len);
        RPC(RPC_SUSPICIOUS_PROCESS, &bsSend, HIGH_PRIORITY,
            RELIABLE_SEQUENCED, NULL, false);
        bsSend.ResetWritePointer();
    }

    // Terminate game with error message
    void TerminateWithMessage(const std::wstring& processPath, const std::string& reason) {
        std::string pathStr = WideToString(processPath.c_str());

        LogToConsole("\n!!! TERMINATING GAME !!!", "RED");
        LogToConsole("Reason: " + reason, "RED");

        std::string message = "Wraith AI detected unauthorized process!\n\n";
        message += "Process: " + pathStr + "\n\n";
        message += "The game will now close.";

        SendWebhookAsync("**" + GetPlayerName() + " (" + GetHWID() + ")" + "** has had an unauthorized process running, terminating game.\n**Process:** `" + pathStr.c_str() + "` | **Reason:** `" + reason.c_str() + "`");

        // Delayed termination
        std::thread([]() {
            Sleep(5000);
            TerminateProcess(GetCurrentProcess(), 1);
            }).detach();

        SetForegroundWindow(GetDesktopWindow());
        MessageBoxA(NULL, message.c_str(), "Wraith AI - Detection", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_SETFOREGROUND);

        MessageBoxA(NULL, message.c_str(), "Wraith AI - Detection", MB_OK | MB_ICONERROR | MB_TOPMOST);

        ReportSuspiciousProcess(processPath);
    }

    // Check if process was already scanned this session
    bool HasProcessBeenScanned(DWORD pid) {
        std::wstring pidStr = std::to_wstring(pid);
        return scannedProcesses.find(pidStr) != scannedProcesses.end();
    }

    // Mark process as scanned to avoid duplicate checks
    void MarkProcessAsScanned(DWORD pid) {
        std::wstring pidStr = std::to_wstring(pid);
        scannedProcesses.insert(pidStr);
    }

public:
    CProcessScanner() : consoleAllocated(false) {
        InitializeWhitelist();
    }

    // Scan all running processes
    void ScanProcesses() {
        LogToConsole("\n--- Starting Process Scan ---", "CYAN");

        // Get function pointer for process path query
        QFPIN pQueryFullProcessImageName = (QFPIN)GetProcAddress(
            GetModuleHandleW(L"Kernel32.dll"),
            "QueryFullProcessImageNameW");

        // Create process snapshot
        HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE) {
            LogToConsole("ERROR: Failed to create process snapshot!", "RED");
            MessageBoxA(NULL,
                "Failed to create process snapshot!\nThis might indicate a rootkit.\n\nThe game will now close.",
                "Anti-Cheat - Snapshot Blocked",
                MB_OK | MB_ICONERROR | MB_TOPMOST);
            ReportSuspiciousProcess(L"SNAPSHOT_BLOCKED");
            TerminateProcess(GetCurrentProcess(), 1);
            return;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        int processCount = 0;
        int whitelistedCount = 0;
        int legitimateCount = 0;
        int suspiciousCount = 0;

        if (Process32FirstW(hProcessSnap, &pe32)) {
            while (Process32NextW(hProcessSnap, &pe32)) {
                processCount++;

                // Skip already scanned processes
                if (HasProcessBeenScanned(pe32.th32ProcessID)) {
                    continue;
                }

                std::string procNameStr = WideToString(pe32.szExeFile);

                // Check whitelist first
                if (IsWhitelistedProcess(pe32.szExeFile)) {
                    LogToConsole("[OK - WHITELISTED] " + procNameStr, "GREEN");
                    whitelistedCount++;
                    MarkProcessAsScanned(pe32.th32ProcessID);
                    continue;
                }

                // Adjust process token for access
                HANDLE process = OpenProcess(TOKEN_ADJUST_PRIVILEGES,
                    FALSE, pe32.th32ProcessID);
                if (process) {
                    AdjustTokens(process);
                    CloseHandle(process);
                }

                // Open process handle
                HANDLE pHandle = NULL;
                if (pQueryFullProcessImageName != NULL) {
                    pHandle = OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                        FALSE, pe32.th32ProcessID);
                }
                else {
                    pHandle = OpenProcess(
                        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE,
                        FALSE, pe32.th32ProcessID);
                }

                if (pHandle != NULL) {
                    wchar_t processpath[MAX_PATH] = { 0 };

                    // Get full process path
                    if (pQueryFullProcessImageName != NULL) {
                        DWORD size = MAX_PATH;
                        pQueryFullProcessImageName(pHandle, 0, processpath, &size);
                    }
                    else {
                        GetModuleFileNameExW(pHandle, NULL, processpath, MAX_PATH);
                    }

                    std::wstring fullPath(processpath);
                    std::wstring procName = pe32.szExeFile;
                    std::string fullPathStr = WideToString(processpath);

                    // Check 1: Suspicious name
                    if (IsSuspiciousName(procName)) {
                        LogToConsole("[BLOCKED - SUSPICIOUS NAME] " + procNameStr + " -> " + fullPathStr, "RED");
                        suspiciousCount++;

                        TerminateProcess(pHandle, 0);
                        CloseHandle(pHandle);
                        CloseHandle(hProcessSnap);

                        std::wstring fullInfo = procName + L"\n" + fullPath;
                        TerminateWithMessage(fullInfo, "Suspicious process name detected");
                        return;
                    }

                    // Check 2: Legitimate location
                    if (wcslen(processpath) > 0 && IsLegitimateLocation(fullPath)) {
                        LogToConsole("[OK - LEGIT LOCATION] " + procNameStr + " -> " + fullPathStr, "GREEN");
                        legitimateCount++;
                        MarkProcessAsScanned(pe32.th32ProcessID);
                        CloseHandle(pHandle);
                        continue;
                    }

                    // Check 3: Unauthorized location
                    if (wcslen(processpath) > 0) {
                        LogToConsole("[BLOCKED - UNAUTHORIZED] " + procNameStr + " -> " + fullPathStr, "RED");
                        suspiciousCount++;

                        TerminateProcess(pHandle, 0);
                        CloseHandle(pHandle);
                        CloseHandle(hProcessSnap);

                        std::wstring fullInfo = procName + L"\n" + fullPath;
                        TerminateWithMessage(fullInfo, "Unauthorized application from non-legitimate location");
                        return;
                    }

                    // Check 4: Fileless execution
                    DWORD err = GetLastError();
                    if (err == ERROR_FILE_INVALID || !DoesFileExist(fullPath)) {
                        LogToConsole("[BLOCKED - FILELESS] " + procNameStr + " -> " + fullPathStr, "RED");
                        suspiciousCount++;

                        TerminateProcess(pHandle, 0);
                        CloseHandle(pHandle);
                        CloseHandle(hProcessSnap);

                        std::wstring fullInfo = procName + L"\n" + fullPath;
                        TerminateWithMessage(fullInfo, "Process file does not exist (fileless injection)");
                        return;
                    }

                    MarkProcessAsScanned(pe32.th32ProcessID);
                    CloseHandle(pHandle);
                }
            }
        }

        CloseHandle(hProcessSnap);

        // Log scan summary
        LogToConsole("--- Scan Complete ---", "CYAN");
        LogToConsole("Total Processes: " + std::to_string(processCount), "");
        LogToConsole("Whitelisted: " + std::to_string(whitelistedCount), "GREEN");
        LogToConsole("Legitimate: " + std::to_string(legitimateCount), "GREEN");
        LogToConsole("Suspicious: " + std::to_string(suspiciousCount), "RED");
    }

    // Start continuous monitoring thread
    void StartMonitoring() {
        AdjustTokens(GetCurrentProcess());
        isRunning = true;

        scanThread = std::thread([this]() {
            LogToConsole("Process scanner initialized. Waiting 5 seconds before first scan...", "YELLOW");
            std::this_thread::sleep_for(std::chrono::seconds(5));

            while (isRunning) {
                try {
                    ScanProcesses();
                }
                catch (const std::exception& e) {
                    std::string msg = "Exception in process scanner:\n";
                    msg += e.what();
                    LogToConsole(msg, "RED");
                    MessageBoxA(NULL, msg.c_str(), "Anti-Cheat Error", MB_OK | MB_ICONERROR);
                    TerminateProcess(GetCurrentProcess(), 1);
                }
                catch (...) {
                    LogToConsole("Unknown exception in process scanner!", "RED");
                    MessageBoxA(NULL,
                        "Unknown exception in process scanner!",
                        "Anti-Cheat Error",
                        MB_OK | MB_ICONERROR);
                    TerminateProcess(GetCurrentProcess(), 1);
                }
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
            });
        scanThread.detach();
    }

    // Stop monitoring and cleanup
    void StopMonitoring() {
        isRunning = false;
        if (consoleAllocated) {
            FreeConsole();
        }
    }
};

static CProcessScanner g_ProcessScanner;

// Public API to start process scanning
void StartProcessScanning() {
    g_ProcessScanner.StartMonitoring();
}

// Public API to stop process scanning
void StopProcessScanning() {
    g_ProcessScanner.StopMonitoring();
}
