// utils.cpp
#include "main.h"

// String conversion utilities
std::string WideToAnsi(const wchar_t* wideStr) {
    if (!wideStr) return "";
    int bufferSize = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, nullptr, 0, nullptr, nullptr);
    if (bufferSize <= 0) return "";
    std::vector<char> buffer(bufferSize);
    int resultSize = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, buffer.data(), bufferSize, nullptr, nullptr);
    if (resultSize <= 0) return "";
    return std::string(buffer.data());
}

std::string WideToString(const wchar_t* wstr) {
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    std::string result(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], size_needed, nullptr, nullptr);
    return result;
}

std::string EscapeBackslashes(const std::string& input) {
    std::string escaped;
    escaped.reserve(input.size());
    for (char c : input) {
        if (c == '\\') escaped += "\\\\";
        else escaped += c;
    }
    return escaped;
}

std::string BytesToHexString(const BYTE* data, DWORD len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (DWORD i = 0; i < len; ++i) {
        oss << std::setw(2) << (int)data[i];
    }
    return oss.str();
}

// Process utilities
DWORD GetProcessID(const std::wstring& processName) {
    DWORD processID = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    if (Process32FirstW(snapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                processID = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }
    CloseHandle(snapshot);
    return processID;
}

// Crypto utilities
std::string GetFileSHA256_WinCrypto(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filePath << "\n";
        return "";
    }

    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    BYTE buffer[8192];
    DWORD bytesRead = 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "CryptAcquireContext failed, error: " << GetLastError() << "\n";
        return "";
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        std::cerr << "CryptCreateHash failed, error: " << GetLastError() << "\n";
        CryptReleaseContext(hProv, 0);
        return "";
    }

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

    DWORD hashLen = 0;
    DWORD hashLenSize = sizeof(DWORD);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&hashLen), &hashLenSize, 0)) {
        std::cerr << "CryptGetHashParam(HP_HASHSIZE) failed, error: " << GetLastError() << "\n";
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    std::vector<BYTE> hash(hashLen);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0)) {
        std::cerr << "CryptGetHashParam(HP_HASHVAL) failed, error: " << GetLastError() << "\n";
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return BytesToHexString(hash.data(), hashLen);
}

// Network utilities
std::string DownloadTextFromURL(const char* url) {
    HINTERNET hInternet = InternetOpenA("Wraith-Client", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return "";

    HINTERNET hFile = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hFile) {
        InternetCloseHandle(hInternet);
        return "";
    }

    char buffer[1024];
    DWORD bytesRead = 0;
    std::string result;

    while (InternetReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead != 0) {
        buffer[bytesRead] = 0;
        result += buffer;
    }

    InternetCloseHandle(hFile);
    InternetCloseHandle(hInternet);
    return result;
}
