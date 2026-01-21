// webhook_sender.cpp - Discord Webhook Handler (SIMPLE - NO EMBED)
#include "main.h"
#include "Discord.h"
#include <string>
#include <thread>
#include <iostream>
#include "utils.h"

extern std::string GetHWID();

static const std::string DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1462435163173552320/3mogzxuvNXokBrFWBzlgG69fhlUh_D3dKf9oQarOmxCUQXoTeWYKRNTedAIHpI8ySL__";
static const std::string DEBUG_URL = "https://discord.com/api/webhooks/1462423142315065490/E0ZdhgXW8IOEjogEioUJXivOGA9bo1pxm7BU3AfCQmtrT7LBJumQGraAQQlVk2mVDQw5";
static const std::string DUMP_URL = "https://discord.com/api/webhooks/1463600707801452767/aJ9sgOfu7rouf5Ela5oq8ItumuyOegXXFn9TrYNNBUWdnwQ5DBEspZMLrZpWxZwi5s8B";

// Async webhook sender for detections (MESSAGE ONLY - NO EMBED)
void SendDetectionToDiscord(const std::string& dllName, const std::string& fullPath, float aiConfidence) {
    std::thread([dllName, fullPath, aiConfidence]() {
        try {
            std::string pcName = GetComputerName();
            std::string hwid = GetHWID();

            // Build message with line breaks
            std::string message = "**"+GetPlayerName()+"" + " (" + hwid /* + " | " + pcName*/ + ")**: unauthorized " + dllName + " was injected, terminating game!\n**Path:** `" + fullPath + "` | **Confidence:** `" + std::to_string((int)(aiConfidence * 100)) + "%`";

            DiscordWebhook webhook(DISCORD_WEBHOOK_URL);
            webhook.setContent(message);
            webhook.setUsername("Wraith AI");
            webhook.execute();

            std::thread([]() {
                Sleep(2000);  // Small delay to show MessageBox
                TerminateProcess(GetCurrentProcess(), 1);
                }).detach();
            std::cout << "[DISCORD] Detection logged successfully!" << std::endl;
        }
        catch (const std::exception& e) {
            std::cout << "[DISCORD] Error: " << e.what() << std::endl;
        }
        catch (...) {
            std::cout << "[DISCORD] Unknown error sending webhook" << std::endl;
        }
        }).detach();

    std::cout << "[DISCORD] Logging detection in background..." << std::endl;
}

// Simple async message sender
void SendWebhookAsync(const std::string& message) {
    std::thread([message]() {
        try {
            Sleep(1000);

            DiscordWebhook webhook(DISCORD_WEBHOOK_URL);
            webhook.setContent(message);
            webhook.setUsername("Wraith AI");
            webhook.execute();

            std::cout << "[WEBHOOK] Message sent!" << std::endl;
        }
        catch (...) {
            std::cout << "[WEBHOOK] Failed to send!" << std::endl;
        }
        }).detach();
}

void SendWebhookAsync2(const std::string& message) {
    std::thread([message]() {
        try {
            Sleep(1000);

            DiscordWebhook webhook(DEBUG_URL);
            webhook.setContent(message);
            webhook.setUsername("Wraith AI");
            webhook.execute();

            std::cout << "[WEBHOOK] Message sent!" << std::endl;
        }
        catch (...) {
            std::cout << "[WEBHOOK] Failed to send!" << std::endl;
        }
        }).detach();
}

void SendMemoryAlertToDiscord(LPVOID address, SIZE_T size) {
    std::thread([address, size]() {
        try {
            // Get timestamp
            SYSTEMTIME st;
            GetLocalTime(&st);

            // Get process info
            char processPath[MAX_PATH];
            GetModuleFileNameA(NULL, processPath, MAX_PATH);

            // Extract just the process name
            std::string procName = processPath;
            size_t lastSlash = procName.find_last_of("\\/");
            if (lastSlash != std::string::npos) {
                procName = procName.substr(lastSlash + 1);
            }

            // Get current HWID or player info if available
            // std::string hwid = GetHWID();  // If you have this function

            // Build detailed message
            std::string message = "**Memory Injection Detected - " + GetPlayerName() + "**\n\n";
            message += "**Address:** `0x" + std::to_string((uintptr_t)address) + "`\n";
            message += "**Size:** `" + std::to_string(size / 1024) + " KB` (" + std::to_string(size) + " bytes)\n";
            message += "**Type:** Private Executable Memory\n";
            message += "**Process:** `" + procName + "`\n";
            message += "**Time:** " + std::to_string(st.wYear) + "-" +
                (st.wMonth < 10 ? "0" : "") + std::to_string(st.wMonth) + "-" +
                (st.wDay < 10 ? "0" : "") + std::to_string(st.wDay) + " " +
                (st.wHour < 10 ? "0" : "") + std::to_string(st.wHour) + ":" +
                (st.wMinute < 10 ? "0" : "") + std::to_string(st.wMinute) + ":" +
                (st.wSecond < 10 ? "0" : "") + std::to_string(st.wSecond) + "\n";

            // Add protection flags info
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(address, &mbi, sizeof(mbi))) {
                message += "**Protection:** ";
                if (mbi.Protect & PAGE_EXECUTE_READWRITE) message += "RWX (Highly Suspicious)";
                else if (mbi.Protect & PAGE_EXECUTE_READ) message += "RX";
                else if (mbi.Protect & PAGE_EXECUTE) message += "X";
                message += "\n";
            }

            DiscordWebhook webhook(DUMP_URL);
            webhook.setContent(message);
            webhook.setUsername("Wraith AI - Memory Scanner");
            webhook.execute();

            std::cout << "[WEBHOOK] ✅ Detailed alert sent!" << std::endl;
        }
        catch (const std::exception& e) {
            std::cout << "[WEBHOOK] ❌ Failed: " << e.what() << std::endl;
        }
        catch (...) {
            std::cout << "[WEBHOOK] ❌ Error!" << std::endl;
        }
        }).detach();
}







