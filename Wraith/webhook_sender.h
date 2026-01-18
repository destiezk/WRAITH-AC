// webhook_sender.h - Discord Webhook Handler Header
#pragma once
#include <string>

// Send detection alert to Discord
void SendDetectionToDiscord(const std::string& dllName, const std::string& fullPath, float aiConfidence);

// Send simple message to Discord
void SendWebhookAsync(const std::string& message);
void SendWebhookAsync2(const std::string& message);