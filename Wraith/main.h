#pragma once
#include <Windows.h>
#include <cstdint>
#include <random>
#include <d3d9.h>
#include <d3dx9.h>
#include <string>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_set>
#include <mutex>

#include "MinHook.h"
#pragma comment(lib, "libMinHook.x86.lib")

#include "detours.h"
#pragma comment(lib, "detours.lib")

#include "BitStream.h"
#include "RakClient.h"
#include "base64.h"
#include "samp.h"
// #include "hwidwin.h"  // REMOVE THIS LINE

#include <bcrypt.h>
#include <vector>
#include <iomanip>
#include <tlhelp32.h>
#include <psapi.h>
#include <locale>
#include <wininet.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wininet.lib")

// ============================
// TYPE DEFINITIONS
// ============================
typedef void(__thiscall* tRegisterAsRemoteProcedureCall)(void*, int*, void(*)(RPCParameters*));
typedef bool(__thiscall* tRPC)(void*, int*, BitStream*, PacketPriority, PacketReliability, char, bool);

// ============================
// GLOBAL DECLARATIONS
// ============================
extern std::string global_message;
extern uint32_t dwSAMPAddr;
extern tRPC oRPC;

// ============================
// FUNCTION DECLARATIONS
// ============================
// From utils.cpp
std::string WideToAnsi(const wchar_t* wideStr);
std::string WideToString(const wchar_t* wstr);
std::string EscapeBackslashes(const std::string& input);
std::string BytesToHexString(const BYTE* data, DWORD len);
DWORD GetProcessID(const std::wstring& processName);
std::string GetFileSHA256_WinCrypto(const std::string& filePath);
std::string DownloadTextFromURL(const char* url);

// From rpc_handlers.cpp
bool RPC(int uniqueID, BitStream* bitStream, PacketPriority priority,
    PacketReliability reliability, char orderingChannel, bool shiftTimestamp);
void RegisterAsRemoteProcedureCall(int uniqueID, void(*functionPointer)(RPCParameters*));
void UpdateHistory();
void SendListofDLL(RPCParameters* rpcParms);
void Wraith_ReadMemory(RPCParameters* rpcParms);
void ListAsiFilesInCurrentDirectory(RPCParameters* rpcParms);
void AC_ChallengeRPC(RPCParameters* rpcParms);

// From dll_detector.cpp
void StartLoadLibraryDetectionAndWorker();
void StopLoadLibraryDetectionAndWorker();