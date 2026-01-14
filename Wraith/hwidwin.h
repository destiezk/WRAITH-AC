#include <windows.h>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>

using namespace std;

inline string ToBase36(unsigned int value)
{
    const char* chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    string result;
    do {
        result = chars[value % 36] + result;
        value /= 36;
    } while (value > 0);
    return result;
}

inline string GetHWID()
{
    UCHAR szFileSys[255], szVolNameBuff[255];
    DWORD dwSerial, dwMFL, dwSysFlags;

    if (!GetVolumeInformationA("C:\\", (LPSTR)szVolNameBuff, 255, &dwSerial, &dwMFL, &dwSysFlags, (LPSTR)szFileSys, 255))
    {
        return "ERROR_NO_ADMIN";
    }

    // Convert to base36 to avoid weird ASCII characters
    string hwid = ToBase36(dwSerial);

    // Optionally add a small transformation (like XOR or shifting) to obfuscate
    for (auto& c : hwid)
    {
        if (c >= '0' && c <= '9')
            c = 'A' + (c - '0'); // Convert digits to A-J
        else
            c = ((c - 'A' + 13) % 26) + 'A'; // Simple ROT13 for letters
    }

    return hwid;
}