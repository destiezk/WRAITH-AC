#include "main.h"

namespace fs = std::filesystem;
using namespace std;
std::string global_message = "";

uint32_t dwSAMPAddr = NULL;

typedef void(__thiscall* tRegisterAsRemoteProcedureCall)(void*, int*, void(*) (RPCParameters*));
typedef bool(__thiscall* tRPC)(void*, int*, BitStream*, PacketPriority, PacketReliability, char, bool);
tRPC oRPC;

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

	bsSend.Write<uint16_t>(0x000000100009);
	bsSend.Write<uint32_t>(0xB17909);

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

	ExitThread(0);
}

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
