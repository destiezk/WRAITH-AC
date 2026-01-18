// webhook_sender.cpp - Discord Webhook Handler (SIMPLE - NO EMBED)
#include "main.h"
#include "Discord.h"
#include <string>
#include <thread>
#include <iostream>
#include "utils.h"

extern std::string GetHWID();

static const std::string DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1458145903855534293/1iBIzm1EPU5RhnEACsroFFiVqBcCMwuv2Y_AkPc4nOon8BtUebeQ5EYsIPXMyf_S7QSm";
static const std::string DEBUG_URL = "https://discord.com/api/webhooks/1462423142315065490/E0ZdhgXW8IOEjogEioUJXivOGA9bo1pxm7BU3AfCQmtrT7LBJumQGraAQQlVk2mVDQw5";

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


