// main.cpp
#include "main.h"
#include "Discord.h"

// At the TOP of the file
HINSTANCE g_hInstance = NULL;
namespace fs = std::filesystem;
using namespace std;

// Global definitions (not extern)
std::string global_message = "";
uint32_t dwSAMPAddr = NULL;
tRPC oRPC;

#define AC_VERSION 104
#define VERSION_URL "https://anticheat.fsc-clan.eu/ac_version.txt"
#define AC_CHALLENGE_RPC 245
#define RPC_WRAITH_READ_MEMORY 200

// Forward declarations from other files
extern void RegisterAsRemoteProcedureCall(int uniqueID, void(*functionPointer)(RPCParameters*));
extern void UpdateHistory();
extern void SendListofDLL(RPCParameters* rpcParms);
extern void Wraith_ReadMemory(RPCParameters* rpcParms);
extern void ListAsiFilesInCurrentDirectory(RPCParameters* rpcParms);
extern void AC_ChallengeRPC(RPCParameters* rpcParms);
extern void StartLoadLibraryDetectionAndWorker();
extern void StartProcessScanning();
extern void StopProcessScanning();
extern std::string DownloadTextFromURL(const char* url);

void InitAntiCheat() {
    StartLoadLibraryDetectionAndWorker();
    StartProcessScanning();
}

void ShutdownAntiCheat() {
    StopLoadLibraryDetectionAndWorker();
    StopProcessScanning();
}

void CheckAC_Version_From_Website() {
    std::string txt = DownloadTextFromURL(VERSION_URL);
    if (txt.empty()) {
        MessageBoxA(NULL, "ERROR - Disable Antivirus", "Wraith-Client", MB_OK | MB_ICONERROR);
        ExitProcess(0);
        return;
    }

    int requiredVersion = atoi(txt.c_str());
    if (requiredVersion == 0) return;

    if (requiredVersion > AC_VERSION) {
        MessageBoxA(NULL,
            "Your Anti-Cheat version is OUTDATED.\n\n"
            "Please download the newest version from www.anticheat.fsc-clan.eu",
            "Wraith-Client", MB_OK | MB_ICONERROR);
        ExitProcess(0);
    }
}

void mainThread() {
    pSAMP = new SAMPFramework();
    while (!pSAMP->tryInit()) Sleep(100);

    StartLoadLibraryDetectionAndWorker();
    CheckAC_Version_From_Website();
    InitAntiCheat();

    ExitThread(0);
}

bool __fastcall hkRPC(void* pThis, void* pUnk, int* uniqueID, BitStream* bitStream,
    PacketPriority priority, PacketReliability reliability,
    char orderingChannel, bool shiftTimestamp) {

    if (*uniqueID == RPC_ClientJoin) {
        UpdateHistory();
        RegisterAsRemoteProcedureCall(65566, SendListofDLL);
        RegisterAsRemoteProcedureCall(RPC_WRAITH_READ_MEMORY, Wraith_ReadMemory);
        RegisterAsRemoteProcedureCall(65564, ListAsiFilesInCurrentDirectory);
        RegisterAsRemoteProcedureCall(AC_CHALLENGE_RPC, AC_ChallengeRPC);
    }

    return oRPC(pThis, uniqueID, bitStream, priority, reliability, orderingChannel, shiftTimestamp);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        g_hInstance = hModule;  // ← Save it here
        MH_Initialize();
        dwSAMPAddr = reinterpret_cast<uint32_t>(LoadLibraryA("samp.dll"));
        MH_CreateHook(reinterpret_cast<void*>(dwSAMPAddr + 0x30B30), &hkRPC,
            reinterpret_cast<void**>(&oRPC));
        MH_EnableHook(reinterpret_cast<void*>(dwSAMPAddr + 0x30B30));
        CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)mainThread, NULL, NULL, NULL);
    }
    return TRUE;
}
