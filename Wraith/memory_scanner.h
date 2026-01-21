#pragma once
#include <windows.h>
#include <set>
#include <string>

struct MemorySnapshot {
    LPVOID address;
    SIZE_T size;

    bool operator<(const MemorySnapshot& other) const {
        return address < other.address;
    }
};

class MemoryScanner {
public:
    MemoryScanner();
    ~MemoryScanner();

    void TakeSnapshot();
    bool CheckForNewRegions();
    void StartMonitoring();
    void StopMonitoring();

private:
    std::set<MemorySnapshot> snapshot;
    bool running;
    HANDLE thread;

    bool alertShown;

    // ADD THIS [web:95]
    bool DumpSuspiciousRegion(LPVOID address, SIZE_T size, std::string& outFilename);

    static DWORD WINAPI MonitorThread(LPVOID param);
};
