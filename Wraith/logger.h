#pragma once
#include <string>

namespace DllLogger {
    // Inicializálás
    void Initialize();

    // Log feltöltése szerverre HWID-dal
    bool UploadDetection(const std::string& dllName, const std::string& fullPath, const std::string& hwid);

    // Helper funkciók
    std::string GetTimestamp();
    std::string GetComputerName();
}
