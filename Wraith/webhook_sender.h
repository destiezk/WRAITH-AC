// webhook_sender.h - Discord Webhook Handler Header
#pragma once
#include <string>


void SendDetectionToDiscord(const std::string& dllName, const std::string& fullPath, float aiConfidence);


void SendWebhookAsync(const std::string& message);
void SendWebhookAsync2(const std::string& message);
void SendMemoryAlertToDiscord(LPVOID address, SIZE_T size);