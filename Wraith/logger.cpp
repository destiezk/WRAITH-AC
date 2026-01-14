#include "main.h"
#include "logger.h"
#include <windows.h>
#include <fstream>
#include <ctime>
#include <vector>

namespace DllLogger {

    // XOR titkosítás
    static std::string SimpleEncrypt(const std::string& data) {
        std::string result = data;
        const char key[] = "lofaszhabbal";

        for (size_t i = 0; i < result.size(); i++) {
            result[i] ^= key[i % (sizeof(key) - 1)];
        }
        return result;
    }

    // URL encode
    static std::string UrlEncode(const std::string& str) {
        std::string result;
        for (unsigned char c : str) {
            if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                result += c;
            }
            else {
                char hex[4];
                sprintf_s(hex, "%%%02X", c);
                result += hex;
            }
        }
        return result;
    }

    // Base64 encode
    static std::string Base64Encode(const std::string& data) {
        static const char* base64_chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        std::string ret;
        int i = 0;
        unsigned char char_array_3[3];
        unsigned char char_array_4[4];

        for (unsigned char c : data) {
            char_array_3[i++] = c;
            if (i == 3) {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for (i = 0; i < 4; i++)
                    ret += base64_chars[char_array_4[i]];
                i = 0;
            }
        }

        if (i) {
            for (int j = i; j < 3; j++)
                char_array_3[j] = '\0';

            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

            for (int j = 0; j < i + 1; j++)
                ret += base64_chars[char_array_4[j]];

            while (i++ < 3)
                ret += '=';
        }

        return ret;
    }

    std::string GetTimestamp() {
        time_t now = time(0);
        char buf[80];
        struct tm timeinfo;
        localtime_s(&timeinfo, &now);
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &timeinfo);
        return std::string(buf);
    }

    std::string GetComputerName() {
        char buffer[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(buffer);
        if (GetComputerNameA(buffer, &size)) {
            return std::string(buffer);
        }
        return "Unknown";
    }

    void Initialize() {
        CreateDirectoryA("logs", NULL);
    }

    bool UploadDetection(const std::string& dllName, const std::string& fullPath, const std::string& hwid) {
        try {
            std::string logMsg = "=== DLL DETECTION ===\n";
            logMsg += "Time: " + GetTimestamp() + "\n";
            logMsg += "Computer: " + GetComputerName() + "\n";
            logMsg += "HWID: " + hwid + "\n";
            logMsg += "DLL Name: " + dllName + "\n";
            logMsg += "Full Path: " + fullPath + "\n";
            logMsg += "=====================\n\n";

            std::string encrypted = SimpleEncrypt(logMsg);
            std::string encoded = Base64Encode(encrypted);
            std::string postData = "log=" + UrlEncode(encoded);

            HINTERNET hInternet = InternetOpenA(
                "AntiCheat/1.0",
                INTERNET_OPEN_TYPE_DIRECT,
                NULL,
                NULL,
                0
            );

            if (!hInternet) return false;

            HINTERNET hConnect = InternetConnectA(
                hInternet,
                "anticheat.fsc-clan.eu",  // NEM /logs itt!
                INTERNET_DEFAULT_HTTPS_PORT,
                NULL,
                NULL,
                INTERNET_SERVICE_HTTP,
                0,
                0
            );

            if (!hConnect) {
                InternetCloseHandle(hInternet);
                return false;
            }

            HINTERNET hRequest = HttpOpenRequestA(
                hConnect,
                "POST",
                "/logs/upload_log.php",  // /logs itt van!
                NULL,
                NULL,
                NULL,
                INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE,
                0
            );

            if (!hRequest) {
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hInternet);
                return false;
            }

            const char* headers = "Content-Type: application/x-www-form-urlencoded\r\n";

            BOOL result = HttpSendRequestA(
                hRequest,
                headers,
                (DWORD)strlen(headers),
                (LPVOID)postData.c_str(),
                (DWORD)postData.length()
            );

            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);

            return result == TRUE;
        }
        catch (...) {
            // Ha nincs net, írjon backup-ot
            try {
                std::ofstream backup("logs\\backup.log", std::ios::app);
                std::string logMsg = "=== DLL DETECTION (BACKUP) ===\n";
                logMsg += "Time: " + GetTimestamp() + "\n";
                logMsg += "Computer: " + GetComputerName() + "\n";
                logMsg += "HWID: " + hwid + "\n";
                logMsg += "DLL Name: " + dllName + "\n";
                logMsg += "Full Path: " + fullPath + "\n";
                logMsg += "=====================\n\n";
                backup << logMsg;
                backup.close();
            }
            catch (...) {}

            return false;
        }
    }



} // namespace DllLogger
