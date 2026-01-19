#pragma once
#include <windows.h>
#include <set>

struct MemorySnapshot {
    LPVOID address;
    SIZE_T size;

    bool operator<(const MemorySnapshot& other) const {
        return address < other.address;
    }
};

class MemoryScanner {
public:
    MemoryScanner();   // <-- ADD THIS
    ~MemoryScanner();  // <-- ADD THIS

    void TakeSnapshot();
    bool CheckForNewRegions();
    void StartMonitoring();
    void StopMonitoring();

private:
    std::set<MemorySnapshot> snapshot;
    bool running;
    HANDLE thread;

    static DWORD WINAPI MonitorThread(LPVOID param);
};
