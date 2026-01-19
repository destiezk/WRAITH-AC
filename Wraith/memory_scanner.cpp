#include "main.h"
#include "memory_scanner.h"
#include <iostream>

MemoryScanner::MemoryScanner() {
    running = false;
    thread = NULL;
}

MemoryScanner::~MemoryScanner() {
    StopMonitoring();
}

void MemoryScanner::TakeSnapshot() {
    snapshot.clear();

    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = 0;

    while (VirtualQuery(address, &mbi, sizeof(mbi))) {
        MemorySnapshot region;
        region.address = mbi.BaseAddress;
        region.size = mbi.RegionSize;

        snapshot.insert(region);

        address = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }

    std::cout << "[MEMORY] Snapshot taken: " << snapshot.size() << " regions" << std::endl;
}

bool MemoryScanner::CheckForNewRegions() {
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = 0;

    while (VirtualQuery(address, &mbi, sizeof(mbi))) {
        MemorySnapshot current;
        current.address = mbi.BaseAddress;
        current.size = mbi.RegionSize;

        if (snapshot.find(current) == snapshot.end()) {

            // Check if executable [web:56]
            bool isExecutable = (mbi.Protect & PAGE_EXECUTE) ||
                (mbi.Protect & PAGE_EXECUTE_READ) ||
                (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
                (mbi.Protect & PAGE_EXECUTE_WRITECOPY);

            if (isExecutable && mbi.Type == MEM_PRIVATE && mbi.State == MEM_COMMIT) {

                // IGNORE small allocations (< 64KB) - these are trampolines/stubs [web:67]
                if (mbi.RegionSize < 65536) {
                    snapshot.insert(current);  // Add to snapshot and ignore
                    address = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
                    continue;
                }

                // Large executable private memory = INJECTED CODE! [web:56][web:67]
                std::cout << "\n*** [INJECTED CODE DETECTED] ***" << std::endl;
                std::cout << "  Address: 0x" << std::hex << mbi.BaseAddress << std::dec << std::endl;
                std::cout << "  Size: " << (mbi.RegionSize / 1024) << " KB" << std::endl;
                std::cout << "  Type: PRIVATE EXECUTABLE (CHEAT!)" << std::endl;

                return true;  // CHEAT DETECTED
            }

            // Not suspicious, add to snapshot [web:67]
            snapshot.insert(current);
        }

        address = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }

    return false;
}

DWORD WINAPI MemoryScanner::MonitorThread(LPVOID param) {
    MemoryScanner* scanner = (MemoryScanner*)param;

    std::cout << "[MEMORY] Monitoring started (executable memory only)" << std::endl;

    while (scanner->running) {
        Sleep(5000);

        if (scanner->CheckForNewRegions()) {
            MessageBoxA(NULL,
                "Wraith-AC detected code injection!\n\n"
                "New executable memory region detected.\n"
                "This indicates manual mapping or shellcode.\n\n"
                "Game will close.",
                "Wraith-AC - Code Injection Detected",
                MB_OK | MB_ICONERROR);

            TerminateProcess(GetCurrentProcess(), 1);
        }
    }

    return 0;
}

void MemoryScanner::StartMonitoring() {
    running = true;
    thread = CreateThread(NULL, 0, MonitorThread, this, 0, NULL);
    std::cout << "[MEMORY] Monitoring active (watching for executable allocations)" << std::endl;
}

void MemoryScanner::StopMonitoring() {
    running = false;
    if (thread) {
        WaitForSingleObject(thread, 5000);
        CloseHandle(thread);
        thread = NULL;
    }
}
