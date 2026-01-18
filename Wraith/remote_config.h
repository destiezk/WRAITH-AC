#pragma once
#include "main.h"
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

// Simple JSON value extractor (lightweight, C++17 compatible)
inline std::string ExtractJsonString(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\":\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return "";

    pos += searchKey.length();
    size_t endPos = json.find("\"", pos);
    if (endPos == std::string::npos) return "";

    return json.substr(pos, endPos - pos);
}

inline float ExtractJsonFloat(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\":";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return 0.0f;

    pos += searchKey.length();

    // Skip whitespace
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n')) {
        pos++;
    }

    size_t endPos = json.find_first_of(",}", pos);
    if (endPos == std::string::npos) return 0.0f;

    std::string valueStr = json.substr(pos, endPos - pos);

    // Remove trailing whitespace
    valueStr.erase(valueStr.find_last_not_of(" \t\n\r") + 1);

    try {
        return std::stof(valueStr);
    }
    catch (...) {
        return 0.0f;
    }
}

// Download fingerprints from server [web:41]
inline std::string DownloadFingerprintsJSON(const std::string& url) {
    HINTERNET hInternet = InternetOpenA(
        "AntiCheat/2.0",
        INTERNET_OPEN_TYPE_DIRECT,
        NULL,
        NULL,
        0
    );

    if (!hInternet) return "";

    HINTERNET hFile = InternetOpenUrlA(
        hInternet,
        url.c_str(),
        NULL,
        0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE,
        0
    );

    if (!hFile) {
        InternetCloseHandle(hInternet);
        return "";
    }

    std::string result;
    char buffer[4096];
    DWORD bytesRead = 0;

    while (InternetReadFile(hFile, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        result.append(buffer, bytesRead);
    }

    InternetCloseHandle(hFile);
    InternetCloseHandle(hInternet);

    return result;
}

// Forward declaration
struct DllFingerprint;

// Parse JSON and populate fingerprint vector [web:50]
inline std::vector<DllFingerprint> ParseFingerprintsJSON(const std::string& json);
