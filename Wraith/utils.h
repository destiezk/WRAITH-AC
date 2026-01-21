#ifndef UTILS_H
#define UTILS_H

#include <Windows.h>
#include <string>

inline std::string WraithJSON(const std::string& input) {
    std::string output;
    output.reserve(input.size());

    for (char c : input) {
        switch (c) {
        case '\\': output += "\\\\"; break;  
        case '\"': output += "\\\""; break;  
        case '\n': output += "\\n"; break;   
        case '\r': output += "\\r"; break;   
        case '\t': output += "\\t"; break;   
        default:   output += c; break;
        }
    }
    return output;
}


inline std::string GetComputerName() {
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);

    if (GetComputerNameA(computerName, &size)) {
        return std::string(computerName);
    }
    return "Unknown";
}

inline std::string GetPlayerName() {
    HKEY hKey;
    DWORD bufferSize = 0;

    // Open the key
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\SAMP", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return "";
    }

    // First call: get required buffer size
    if (RegQueryValueExA(hKey, "PlayerName", nullptr, nullptr, nullptr, &bufferSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return "";
    }

    // Allocate buffer and read value
    std::vector<char> buffer(bufferSize);
    if (RegQueryValueExA(hKey, "PlayerName", nullptr, nullptr, (LPBYTE)buffer.data(), &bufferSize) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return std::string(buffer.data());
    }

    RegCloseKey(hKey);
    return "";
}

#endif
