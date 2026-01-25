#include "main.h"
#include "memory_scanner.h"
#include "webhook_sender.h"
#include <iostream>
#include <fstream>
#include <sstream>

MemoryScanner::MemoryScanner() {
    running = false;
    alertShown = false;
    thread = NULL;
}

MemoryScanner::~MemoryScanner() {
    StopMonitoring();
}

bool MemoryScanner::DumpSuspiciousRegion(LPVOID address, SIZE_T size, std::string& outFilename) {
    // Create dumps directory
    CreateDirectoryA("wraith_dumps", NULL);

    // Generate filename with timestamp and address
    SYSTEMTIME st;
    GetLocalTime(&st);

    char filename[MAX_PATH];
    sprintf_s(filename, "wraith_dumps/region_0x%p_%04d%02d%02d_%02d%02d%02d_%dKB.bin",
        address,
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond,
        (int)(size / 1024));

    outFilename = filename;

    // Dump memory to file 
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cout << "[DUMP] Failed to create dump file!" << std::endl;
        return false;
    }

    // Write memory contents
    file.write((char*)address, size);
    file.close();

    std::cout << "[DUMP] Saved to: " << filename << std::endl;

    // Also create metadata file
    std::string metaFilename = filename;
    metaFilename += ".txt";

    std::ofstream meta(metaFilename);
    if (meta.is_open()) {
        meta << "Wraith-AC Memory Dump\n";
        meta << "=====================\n";
        meta << "Address: 0x" << std::hex << address << std::dec << "\n";
        meta << "Size: " << (size / 1024) << " KB (" << size << " bytes)\n";
        meta << "Timestamp: " << st.wYear << "-" << st.wMonth << "-" << st.wDay
            << " " << st.wHour << ":" << st.wMinute << ":" << st.wSecond << "\n";
        meta << "Type: Private Executable Memory\n";
        meta << "Detection: New region after baseline\n";
        meta.close();
    }

    return true;
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
            bool isExecutable = (mbi.Protect & PAGE_EXECUTE) ||
                (mbi.Protect & PAGE_EXECUTE_READ) ||
                (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
                (mbi.Protect & PAGE_EXECUTE_WRITECOPY);

            if (isExecutable && mbi.Type == MEM_PRIVATE && mbi.State == MEM_COMMIT) {
                if (mbi.RegionSize < 65536) {
                    snapshot.insert(current);
                    address = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
                    continue;
                }

                std::cout << "\n*** [INJECTED CODE DETECTED] ***" << std::endl;
                std::cout << "  Address: 0x" << std::hex << mbi.BaseAddress << std::dec << std::endl;
                std::cout << "  Size: " << (mbi.RegionSize / 1024) << " KB" << std::endl;

                //SendMemoryAlertToDiscord(mbi.BaseAddress, mbi.RegionSize);
                SendMemoryAlertToDiscord(mbi.BaseAddress, mbi.RegionSize);
                std::cout << "  Status: Sending to Discord...." << std::endl;

                return true;
            }

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
            if (!scanner->alertShown) {
                scanner->alertShown = true;

                std::cout << "[MEMORY] Detection confirmed, closing in 5 seconds..." << std::endl;

                std::thread([]() {
                    Sleep(4000); 
                    TerminateProcess(GetCurrentProcess(), 1);
                    }).detach();

                MessageBoxA(NULL,
                    "Wraith-AC detected code injection!\n\nGame will close in 5 seconds.",
                    "Wraith-AC - Code Injection Detected",
                    MB_OK | MB_ICONERROR);
            }
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
