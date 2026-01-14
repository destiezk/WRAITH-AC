// rpc_handlers.cpp
#include "main.h"
#include "hwidwin.h"

namespace fs = std::filesystem;
using namespace std;

//extern uint32_t dwSAMPAddr;
//extern tRPC oRPC;

// Forward declarations from utils.cpp
extern std::string WideToAnsi(const wchar_t* wideStr);
extern std::string WideToString(const wchar_t* wstr);
extern std::string EscapeBackslashes(const std::string& input);
extern std::string GetFileSHA256_WinCrypto(const std::string& filePath);
extern DWORD GetProcessID(const std::wstring& processName);

// ============================
// RPC WRAPPERS
// ============================
bool RPC(int uniqueID, BitStream* bitStream, PacketPriority priority,
    PacketReliability reliability, char orderingChannel, bool shiftTimestamp) {
    void** pRakClient = *(void***)((*(DWORD*)(dwSAMPAddr + 0x21A0F8)) + 0x3C9);
    return (tRPC(dwSAMPAddr + 0x30B30))(pRakClient, &uniqueID, bitStream, priority,
        reliability, orderingChannel, shiftTimestamp);
}

void RegisterAsRemoteProcedureCall(int uniqueID, void(*functionPointer)(RPCParameters*)) {
    void** pRakClient = *(void***)((*(DWORD*)(dwSAMPAddr + 0x21A0F8)) + 0x3C9);
    return (tRegisterAsRemoteProcedureCall(dwSAMPAddr + 0x30F90))(pRakClient, &uniqueID, functionPointer);
}

// ============================
// AC CHALLENGE-RESPONSE SYSTEM
// ============================
#define AC_CHALLENGE_RPC 245
#define AC_RESPONSE_RPC  181
#define AC_SECRET 0x5F3A9C17u

static uint32_t g_LastNonce = 0;

uint32_t MakeAcToken(uint32_t nonce) {
    uint32_t x = nonce ^ AC_SECRET;
    x = x * 1103515245u + 123456u;
    x ^= 0x00A64351u;
    return x;
}

void SendACData() {
    if (g_LastNonce == 0) return;

    uint32_t token = MakeAcToken(g_LastNonce);
    BitStream bsSend;
    bsSend.Write<uint32_t>(token);
    RPC(AC_RESPONSE_RPC, &bsSend, HIGH_PRIORITY, RELIABLE_SEQUENCED, NULL, false);
    g_LastNonce = 0;
}

void OnACChallenge(BitStream* bs) {
    uint32_t nonce = 0;
    if (!bs->Read(nonce)) return;
    g_LastNonce = nonce;
    SendACData();
}

void AC_ChallengeRPC(RPCParameters* rpcParms) {
    BitStream bs(rpcParms->input, rpcParms->numberOfBitsOfData / 8, false);
    OnACChallenge(&bs);
}

// ============================
// RPC HANDLERS
// ============================
void Wraith_ReadMemory(RPCParameters* rpcParms) {
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

void SendListofDLL(RPCParameters* rpcParms) {
    BitStream bsSend;
    std::wstring processName = L"gta_sa.exe";
    DWORD pid = GetProcessID(processName);
    if (pid == 0) return;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return;

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            wchar_t szModName[MAX_PATH];
            if (GetModuleFileNameExW(hProcess, hMods[i], szModName, MAX_PATH)) {
                std::string injected_dll = EscapeBackslashes(WideToString(szModName));
                std::string uHWID = GetHWID();

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
    CloseHandle(hProcess);
}

void UpdateHistory() {
    BitStream bsSend;
    fs::path current = fs::current_path();

    for (const auto& entry : fs::recursive_directory_iterator(current, fs::directory_options::skip_permission_denied)) {
        if (entry.is_regular_file()) {
            std::string name = entry.path().filename().string();
            uintmax_t size = fs::file_size(entry);
            std::string hash = GetFileSHA256_WinCrypto(entry.path().filename().string());
            std::string uHWID = GetHWID();

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

void ListAsiFilesInCurrentDirectory(RPCParameters* rpcParms) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile(L"*.asi", &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        std::string name = WideToAnsi(findFileData.cFileName);
        if (name.empty() || name.length() > 1024) continue;

        BitStream bsSend;
        uint32_t byteTextLenName = static_cast<uint32_t>(name.length());
        bsSend.Write(byteTextLenName);
        bsSend.Write(name.c_str(), byteTextLenName);
        RPC(65565, &bsSend, HIGH_PRIORITY, RELIABLE_SEQUENCED, NULL, false);
        Sleep(10);
    } while (FindNextFile(hFind, &findFileData));

    FindClose(hFind);
}
