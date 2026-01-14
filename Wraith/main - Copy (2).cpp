// combined_with_loadlibrary_detection.cpp
// Paste into your project. Assumes MinHook is available and initialized in DllMain as in your original code.

#include "main.h"

namespace fs = std::filesystem;
using namespace std;
std::string global_message = "";

uint32_t dwSAMPAddr = NULL;

typedef void(__thiscall* tRegisterAsRemoteProcedureCall)(void*, int*, void(*) (RPCParameters*));
typedef bool(__thiscall* tRPC)(void*, int*, BitStream*, PacketPriority, PacketReliability, char, bool);
tRPC oRPC;

// --- ORIGINAL RPC wrappers (unchanged) ---
bool RPC(int uniqueID, BitStream* bitStream, PacketPriority priority, PacketReliability reliability, char orderingChannel, bool shiftTimestamp)
{
    void** pRakClient = *(void***)((*(DWORD*)(dwSAMPAddr + 0x21A0F8)) + 0x3C9);
    return (tRPC(dwSAMPAddr + 0x30B30))(pRakClient, &uniqueID, bitStream, priority, reliability, orderingChannel, shiftTimestamp);
}

void RegisterAsRemoteProcedureCall(int uniqueID, void(*functionPointer)(RPCParameters*))
{
    void** pRakClient = *(void***)((*(DWORD*)(dwSAMPAddr + 0x21A0F8)) + 0x3C9);
    return (tRegisterAsRemoteProcedureCall(dwSAMPAddr + 0x30F90))(pRakClient, &uniqueID, functionPointer);
}

// --- ORIGINAL helpers (unchanged) ---
DWORD GetProcessID(const std::wstring& processName)
{
    DWORD processID = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    if (Process32FirstW(snapshot, &pe32))
    {
        do
        {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0)
            {
                processID = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return processID;
}

std::string WideToAnsi(const wchar_t* wideStr) {
    if (!wideStr) return "";

    int bufferSize = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, nullptr, 0, nullptr, nullptr);
    if (bufferSize <= 0) return "";

    std::vector<char> buffer(bufferSize);
    int resultSize = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, buffer.data(), bufferSize, nullptr, nullptr);
    if (resultSize <= 0) return "";

    return std::string(buffer.data());
}


std::string BytesToHexString(const BYTE* data, DWORD len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (DWORD i = 0; i < len; ++i) {
        oss << std::setw(2) << (int)data[i];
    }
    return oss.str();
}

std::string GetFileSHA256_WinCrypto(const std::string& filePath) {
    // Open file in binary mode
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filePath << "\n";
        return "";
    }

    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    BYTE buffer[8192];
    DWORD bytesRead = 0;

    // Acquire crypt context
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "CryptAcquireContext failed, error: " << GetLastError() << "\n";
        return "";
    }

    // Create hash object for SHA-256
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        std::cerr << "CryptCreateHash failed, error: " << GetLastError() << "\n";
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // Read file and hash data
    while (file.good()) {
        file.read(reinterpret_cast<char*>(buffer), sizeof(buffer));
        bytesRead = static_cast<DWORD>(file.gcount());
        if (bytesRead > 0) {
            if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
                std::cerr << "CryptHashData failed, error: " << GetLastError() << "\n";
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                return "";
            }
        }
    }

    // Get hash size
    DWORD hashLen = 0;
    DWORD hashLenSize = sizeof(DWORD);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&hashLen), &hashLenSize, 0)) {
        std::cerr << "CryptGetHashParam(HP_HASHSIZE) failed, error: " << GetLastError() << "\n";
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // Get the hash value
    std::vector<BYTE> hash(hashLen);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0)) {
        std::cerr << "CryptGetHashParam(HP_HASHVAL) failed, error: " << GetLastError() << "\n";
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // Cleanup
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    // Convert hash to hex string
    return BytesToHexString(hash.data(), hashLen);
}


std::string EscapeBackslashes(const std::string& input)
{
    std::string escaped;
    escaped.reserve(input.size()); // Optional optimization

    for (char c : input)
    {
        if (c == '\\')
            escaped += "\\\\";
        else
            escaped += c;
    }

    return escaped;
}

std::string WideToString(const wchar_t* wstr)
{
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    std::string result(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], size_needed, nullptr, nullptr);
    return result;
}


// rpc id
#define RPC_WRAITH_READ_MEMORY   200
#define RPC_WRAITH_SCAN_RESULT   201
void Wraith_ReadMemory(RPCParameters* rpcParms)
{
    BitStream bitStream(rpcParms->input, rpcParms->numberOfBitsOfData / 8, false);

    uint32_t address = 0;
    BYTE size = 0;

    bitStream.Read(address);
    bitStream.Read(size);

    BitStream bsSend;
    bsSend.Write<uint32_t>(address);
    bsSend.Write<uint8_t>(size);

    for (auto i = 0; i < size; i++)
        bsSend.Write<BYTE>(*reinterpret_cast<BYTE*>(address + i));

    RPC(201, &bsSend, HIGH_PRIORITY, RELIABLE_SEQUENCED, NULL, false);
    bitStream.ResetWritePointer();
    bsSend.ResetWritePointer();
}

void SendListofDLL(RPCParameters* rpcParms)
{
    BitStream bitStream(rpcParms->input, rpcParms->numberOfBitsOfData / 8, false);

    BitStream bsSend;
    std::vector<std::string> dllinjected;
    std::vector<std::string> wHWID;

    std::wstring processName = L"gta_sa.exe";
    DWORD pid = GetProcessID(processName);
    if (pid == 0)
    {
        std::wcerr << L"Process not found: " << processName << std::endl;
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess)
    {
        std::wcerr << L"Failed to open process. Error: " << GetLastError() << std::endl;
        return;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            wchar_t szModName[MAX_PATH];
            if (GetModuleFileNameExW(hProcess, hMods[i], szModName, MAX_PATH))
            {
                std::string injected_dll = EscapeBackslashes(WideToString(szModName));

                std::string uHWID = GetHWID();

                dllinjected.push_back(injected_dll);
                wHWID.push_back(uHWID);

                uint32_t byteTextLenDLL = static_cast<uint32_t>(injected_dll.length());
                uint32_t byteTextHWID = static_cast<uint32_t>(uHWID.length());

                bsSend.Write(byteTextLenDLL);
                bsSend.Write(injected_dll.c_str(), byteTextLenDLL);
                bsSend.Write(byteTextHWID);
                bsSend.Write(uHWID.c_str(), byteTextHWID);
                RPC(189, &bsSend, HIGH_PRIORITY, RELIABLE_SEQUENCED, NULL, false);
                bsSend.ResetWritePointer();
            }
        }
    }
    else
    {
        std::wcerr << L"Failed to enumerate modules. Error: " << GetLastError() << std::endl;
    }

    CloseHandle(hProcess);
    bsSend.ResetWritePointer();
}


void UpdateHistory()
{
    BitStream bsSend;
    fs::path current = fs::current_path();  // Current directory

    std::vector<std::string> filenames;
    std::vector<uintmax_t> sizes;
    std::vector<std::string> hashes;
    std::vector<BYTE> hashLengths;
    std::vector<std::string> wHWID;

    for (const auto& entry : fs::recursive_directory_iterator(current, fs::directory_options::skip_permission_denied)) {
        if (entry.is_regular_file()) {  // Only files
            std::string name = entry.path().filename().string();
            uintmax_t size = fs::file_size(entry);
            std::string hash = GetFileSHA256_WinCrypto(entry.path().filename().string());
            std::string uHWID = GetHWID();

            filenames.push_back(name);
            sizes.push_back(size);
            hashes.push_back(hash);
            wHWID.push_back(uHWID);

            uint32_t byteTextLenName = strlen(name.c_str());
            uint32_t byteTextLenHash = strlen(hash.c_str());
            uint32_t byteTextHWID = strlen(uHWID.c_str());

            bsSend.Write(byteTextLenName);
            bsSend.Write(name.c_str(), byteTextLenName);
            bsSend.Write<uint32_t>(size);
            bsSend.Write(byteTextLenHash);
            bsSend.Write(hash.c_str(), byteTextLenHash);
            bsSend.Write(byteTextHWID);
            bsSend.Write(uHWID.c_str(), byteTextHWID);

            RPC(183, &bsSend, HIGH_PRIORITY, RELIABLE_SEQUENCED, NULL, false);
            bsSend.ResetWritePointer();
        }
    }
}

void SendACData()
{
    BitStream bsSend;

    bsSend.Write<uint16_t>(0x060971249);
    bsSend.Write<uint32_t>(0xA64351);

    RPC(181, &bsSend, HIGH_PRIORITY, RELIABLE_SEQUENCED, NULL, false);
    bsSend.ResetWritePointer();
}

void ListAsiFilesInCurrentDirectory(RPCParameters* rpcParms) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile(L"*.asi", &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        std::string name = WideToAnsi(findFileData.cFileName);

        // Safety check: skip empty or oversized names
        if (name.empty() || name.length() > 1024) {
            continue;
        }

        BitStream bsSend;
        uint32_t byteTextLenName = static_cast<uint32_t>(name.length());

        bsSend.Write(byteTextLenName);
        bsSend.Write(name.c_str(), byteTextLenName);

        RPC(65565, &bsSend, HIGH_PRIORITY, RELIABLE_SEQUENCED, NULL, false);

        Sleep(10); // Prevent flooding
    } while (FindNextFile(hFind, &findFileData));

    FindClose(hFind);
}

bool __fastcall hkRPC(void* pThis, void* pUnk, int* uniqueID, BitStream* bitStream, PacketPriority priority, PacketReliability reliability, char orderingChannel, bool shiftTimestamp)
{
    if (*uniqueID == RPC_ClientJoin)
    {
        SendACData();
        UpdateHistory();
        RegisterAsRemoteProcedureCall(65566, SendListofDLL);
        RegisterAsRemoteProcedureCall(RPC_WRAITH_READ_MEMORY, Wraith_ReadMemory);
        RegisterAsRemoteProcedureCall(65564, ListAsiFilesInCurrentDirectory);
    }

    return oRPC(pThis, uniqueID, bitStream, priority, reliability, orderingChannel, shiftTimestamp);
}

void mainThread() {
    pSAMP = new SAMPFramework();
    while (!pSAMP->tryInit()) Sleep(100);

    // --- START: worker thread + hook installation (safe, after initialization) ---
    extern void StartLoadLibraryDetectionAndWorker(); // forward declare
    StartLoadLibraryDetectionAndWorker();
    // --- END: worker + hooks ---

    ExitThread(0);
}

// ----------------- BEGIN ADDITIONS: LoadLibrary detection -----------------
#include <unordered_set>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <thread>

// Pawn RPC id to send when a new DLL is detected
#define RPC_NEW_DLL_DETECTED 655910

// Hook typedefs for LoadLibrary functions
typedef HMODULE(WINAPI* tLoadLibraryA)(LPCSTR);
typedef HMODULE(WINAPI* tLoadLibraryW)(LPCWSTR);
typedef HMODULE(WINAPI* tLoadLibraryExA)(LPCSTR, HANDLE, DWORD);
typedef HMODULE(WINAPI* tLoadLibraryExW)(LPCWSTR, HANDLE, DWORD);

// Original pointers (filled by MinHook)
static tLoadLibraryA oLoadLibraryA = nullptr;
static tLoadLibraryW oLoadLibraryW = nullptr;
static tLoadLibraryExA oLoadLibraryExA = nullptr;
static tLoadLibraryExW oLoadLibraryExW = nullptr;

// Thread-safe queue + set for dedupe
static std::mutex g_queueMutex;
static std::condition_variable g_queueCv;
static std::queue<std::string> g_dllQueue;
static std::unordered_set<std::string> g_seenDlls; // to avoid duplicates
static std::atomic<bool> g_workerRunning{ false };
static std::thread g_workerThread;

// Small helper: trim path -> filename and convert wide->utf8
static std::string FilenameFromAnsiPath(const char* pathA)
{
    if (!pathA) return std::string();
    try {
        fs::path p(pathA);
        return p.filename().string();
    }
    catch (...) {
        return std::string(pathA);
    }
}
static std::string FilenameFromWidePath(const wchar_t* pathW)
{
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

// Safe small RPC sending function matching Pawn format: [uint32 length][bytes]
static bool CanSendRPC()
{
    if (dwSAMPAddr == 0) return false;
    if (oRPC == nullptr) return false;
    return true;
}

static void SendDllNameToServer_Safe(const std::string& dllName)
{
    try {
        if (!CanSendRPC()) return;

        size_t len = dllName.size();
        if (len == 0) return;
        if (len >= 256) len = 255; // Pawn expects <256

        BitStream bsSend;
        uint32_t nameLen = static_cast<uint32_t>(len);
        bsSend.Write<uint32_t>(nameLen);
        bsSend.Write(dllName.c_str(), nameLen);

        RPC(RPC_NEW_DLL_DETECTED, &bsSend, HIGH_PRIORITY, RELIABLE_SEQUENCED, NULL, false);
        bsSend.ResetWritePointer();
    }
    catch (...) {
        // swallow to avoid crash
    }
}

// Worker thread: waits for enqueued filenames and sends RPCs
static void WorkerThreadFunc()
{
    g_workerRunning.store(true);
    while (g_workerRunning.load())
    {
        std::unique_lock<std::mutex> lk(g_queueMutex);
        g_queueCv.wait(lk, [] { return !g_dllQueue.empty() || !g_workerRunning.load(); });

        while (!g_dllQueue.empty())
        {
            std::string name = std::move(g_dllQueue.front());
            g_dllQueue.pop();
            lk.unlock();

            // send name via RPC
            SendDllNameToServer_Safe(name);

            lk.lock();
        }
    }
}

static bool IsWhitelistedDll(std::string filename)
{
    if (filename.empty()) return true;

    // normalize to lowercase
    std::transform(filename.begin(), filename.end(), filename.begin(), ::tolower);

    // ensure .dll extension for consistency
    if (filename.find('.') == std::string::npos)
        filename += ".dll";

    // Patterns and common modules that should be ignored
    static const std::vector<std::string> safeNames = {
        // Windows core/system
        "kernel32.dll", "user32.dll", "gdi32.dll", "advapi32.dll",
        "shell32.dll", "ole32.dll", "oleaut32.dll", "comdlg32.dll",
        "rpcrt4.dll", "msvcrt.dll", "winmm.dll", "ws2_32.dll",
        "uxtheme.dll", "shlwapi.dll", "powrprof.dll", "comctl32.dll",
        "imm32.dll", "sechost.dll", "setupapi.dll", "bcrypt.dll",
        "bcryptprimitives.dll", "version.dll", "ntdll.dll",

        // Windows “api-ms-win-*” stubs
        "api-ms-win-core", "api-ms-win-crt", "api-ms-win-appmodel",

        // Graphics and DirectX
        "opengl32.dll", "d3dcompiler_47.dll", "d3dx9_42.dll", "d3dx9_43.dll",
        "dxgi.dll", "nvldumd.dll", "amdxx.dll", "atiadlxx.dll", "atidxx32.dll",

        // SA-MP / GTA default DLLs
        "samp.dll", "bass.dll", "vorbis.dll", "vorbisfile.dll",
        "eax.dll", "d3d9.dll",

        // Common overlays / safe external libs
        "discordhook.dll", "nvapi.dll", "nvcuda.dll"
    };

    // substring filters for families
    if (filename.find("api-ms-win-") != std::string::npos)
        return true;

    // match full filename against whitelist
    for (const auto& safe : safeNames)
    {
        if (filename == safe)
            return true;
    }

    return false; // not in whitelist → suspicious
}


static bool EnqueueDetectedDll(const std::string& filename)
{
    if (filename.empty()) return false;

    // skip if known system/game dll
    if (IsWhitelistedDll(filename))
        return false;

    std::string lower = filename;
    for (auto& c : lower) c = (char)::tolower((unsigned char)c);

    std::lock_guard<std::mutex> lock(g_queueMutex);
    if (g_seenDlls.find(lower) != g_seenDlls.end()) return false; // already seen
    g_seenDlls.insert(lower);
    g_dllQueue.push(filename);
    g_queueCv.notify_one();
    return true;
}

// Hook implementations: call original loader first, then enqueue filename (fast)
HMODULE WINAPI hkLoadLibraryA(LPCSTR lpLibFileName)
{
    HMODULE h = NULL;
    if (oLoadLibraryA) h = oLoadLibraryA(lpLibFileName);
    else h = LoadLibraryA(lpLibFileName);

    if (h && lpLibFileName)
    {
        try {
            std::string filename = FilenameFromAnsiPath(lpLibFileName);
            EnqueueDetectedDll(filename);
        }
        catch (...) {}
    }

    return h;
}

HMODULE WINAPI hkLoadLibraryW(LPCWSTR lpLibFileName)
{
    HMODULE h = NULL;
    if (oLoadLibraryW) h = oLoadLibraryW(lpLibFileName);
    else h = LoadLibraryW(lpLibFileName);

    if (h && lpLibFileName)
    {
        try {
            std::string filename = FilenameFromWidePath(lpLibFileName);
            EnqueueDetectedDll(filename);
        }
        catch (...) {}
    }

    return h;
}

HMODULE WINAPI hkLoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    HMODULE h = NULL;
    if (oLoadLibraryExA) h = oLoadLibraryExA(lpLibFileName, hFile, dwFlags);
    else h = LoadLibraryExA(lpLibFileName, hFile, dwFlags);

    if (h && lpLibFileName)
    {
        try {
            std::string filename = FilenameFromAnsiPath(lpLibFileName);
            EnqueueDetectedDll(filename);
        }
        catch (...) {}
    }

    return h;
}

HMODULE WINAPI hkLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    HMODULE h = NULL;
    if (oLoadLibraryExW) h = oLoadLibraryExW(lpLibFileName, hFile, dwFlags);
    else h = LoadLibraryExW(lpLibFileName, hFile, dwFlags);

    if (h && lpLibFileName)
    {
        try {
            std::string filename = FilenameFromWidePath(lpLibFileName);
            EnqueueDetectedDll(filename);
        }
        catch (...) {}
    }

    return h;
}

// Install hooks (call after MH_Initialize and after environment is ready)
static void InstallLoadLibraryHooks()
{
    // Create hooks, ignore unsuccessful returns but you may log them
    MH_CreateHookApi(L"kernel32", "LoadLibraryA", &hkLoadLibraryA, reinterpret_cast<void**>(&oLoadLibraryA));
    MH_CreateHookApi(L"kernel32", "LoadLibraryW", &hkLoadLibraryW, reinterpret_cast<void**>(&oLoadLibraryW));
    MH_CreateHookApi(L"kernel32", "LoadLibraryExA", &hkLoadLibraryExA, reinterpret_cast<void**>(&oLoadLibraryExA));
    MH_CreateHookApi(L"kernel32", "LoadLibraryExW", &hkLoadLibraryExW, reinterpret_cast<void**>(&oLoadLibraryExW));

    MH_EnableHook(&LoadLibraryA);
    MH_EnableHook(&LoadLibraryW);
    MH_EnableHook(&LoadLibraryExA);
    MH_EnableHook(&LoadLibraryExW);
}

// Optional fallback: small polling monitor to pick up modules loaded before hooks installed
static std::atomic<bool> g_pollingRunning{ false };
static std::thread g_pollThread;
static void PollingMonitorFunc()
{
    // start with current set
    std::unordered_set<std::string> localSeen;
    HMODULE mods[1024];
    DWORD cbNeeded = 0;
    if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &cbNeeded))
    {
        unsigned int count = cbNeeded / sizeof(HMODULE);
        for (unsigned int i = 0; i < count; ++i)
        {
            wchar_t full[MAX_PATH] = { 0 };
            if (GetModuleFileNameW(mods[i], full, MAX_PATH))
            {
                std::string f = FilenameFromWidePath(full);
                if (!f.empty()) localSeen.insert(f);
            }
        }
    }

    while (g_pollingRunning.load())
    {
        if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &cbNeeded))
        {
            unsigned int count = cbNeeded / sizeof(HMODULE);
            for (unsigned int i = 0; i < count; ++i)
            {
                wchar_t full[MAX_PATH] = { 0 };
                if (GetModuleFileNameW(mods[i], full, MAX_PATH))
                {
                    std::string f = FilenameFromWidePath(full);
                    if (!f.empty() && localSeen.find(f) == localSeen.end())
                    {
                        localSeen.insert(f);
                        EnqueueDetectedDll(f);
                    }
                }
            }
        }
        Sleep(2000);
    }
}

// Start worker + install hooks. Called from mainThread() after tryInit().
void StartLoadLibraryDetectionAndWorker()
{
    // start worker
    g_workerThread = std::thread(WorkerThreadFunc);

    // install hooks
    InstallLoadLibraryHooks();

    // start optional polling as fallback
   // g_pollingRunning.store(true);
    //g_pollThread = std::thread(PollingMonitorFunc);
}

// Stop worker + hooks (call if unloading)
void StopLoadLibraryDetectionAndWorker()
{
    // stop polling
    g_pollingRunning.store(false);
    if (g_pollThread.joinable()) g_pollThread.join();

    // stop worker
    g_workerRunning.store(false);
    g_queueCv.notify_all();
    if (g_workerThread.joinable()) g_workerThread.join();

    // disable hooks
    MH_DisableHook(&LoadLibraryA);
    MH_DisableHook(&LoadLibraryW);
    MH_DisableHook(&LoadLibraryExA);
    MH_DisableHook(&LoadLibraryExW);
}

// ----------------- END ADDITIONS -----------------

// ----- DllMain: keep your original behavior, but do NOT start worker or install hooks here -----
// (Your original DllMain already initializes MinHook and installs hkRPC; keep that)
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        MH_Initialize();
        dwSAMPAddr = reinterpret_cast<uint32_t>(LoadLibraryA("samp.dll"));
        MH_CreateHook(reinterpret_cast<void*>(dwSAMPAddr + 0x30B30), &hkRPC, reinterpret_cast<void**>(&oRPC));
        MH_EnableHook(reinterpret_cast<void*>(dwSAMPAddr + 0x30B30));
        CreateThread((LPSECURITY_ATTRIBUTES)NULL, (SIZE_T)NULL, (LPTHREAD_START_ROUTINE)mainThread, (LPVOID)NULL, (DWORD)NULL, (LPDWORD)NULL);

        /*const char* message = "Initialization successful";
        const char* title = "Wraith-Client";

        MessageBoxA(NULL, message, title, MB_OK | MB_ICONINFORMATION);*/


    }
    return TRUE;
}
