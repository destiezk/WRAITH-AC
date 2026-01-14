# DLL Detection & Logging System (AI Enhanced)

A robust anti-cheat solution for game servers that detects, logs, and reports unauthorized DLL injections in real time. This system combines traditional API hooking with Machine Learning analysis and Discord-integrated reporting.

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [AI & Machine Learning Pipeline](#ai--machine-learning-pipeline)
- [Discord Integration](#discord-integration)
- [Installation](#installation)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Security Features](#security-features)
- [FAQ](#faq)
- [License](#license)

---

## Features

- **Real-time Detection:** Hooks `LoadLibraryA/W` and `LoadLibraryExA/W` to intercept injections.
- **AI-Driven Analysis:** Utilizes a Python-trained model to analyze DLL features and behavioral signatures.
- **Discord Logging:** Instant alerts sent via Webhooks (replacing legacy PHP backends).
- **Pre-load Scanning:** Scans existing modules at startup using the AI inference engine.
- **Hardware ID (HWID) Tracking:** Unique fingerprinting to identify and ban repeat offenders.
- **Encrypted Payloads:** XOR + Base64 encryption for all data transmitted to Discord.
- **Automatic Mitigation:** Instant process termination upon confirmed malicious detection.

---

## How It Works

### Detection Pipeline

1. **On Game Startup:**
   - Performs a "Deep Scan" of all modules already loaded in memory.
   - Extracts features from these DLLs and passes them through the **AI Inference Engine**.
   - Installs active hooks on the Windows API set using the **MinHook** library.

2. **During Runtime:**
   - Every `LoadLibrary` attempt is intercepted.
   - **Heuristic Check:** Evaluates whitelisted paths (`\Windows\`, `\Program Files\`) and suspicious keywords.
   - **AI Check:** Analyzes the DLL structure for packed sections, suspicious imports, and entry point anomalies.

3. **On Detection:**
   - Gathers metadata: DLL name, full path, HWID, and timestamp.
   - Encrypts the payload and transmits it directly to a designated **Discord Webhook**.
   - Terminates the game process to maintain integrity.

---

## AI & Machine Learning Pipeline

The system moves beyond simple blacklisting by using a predictive model.

* **Training (Python):** A dedicated Python script processes thousands of known clean and malicious DLLs. It extracts features like entropy, export table density, and section characteristics using `pefile`.
* **Model Export:** The trained model is optimized and exported (via JSON or C++ header) to be used by the client-side detection engine.
* **Feature Extraction:** The C++ client performs real-time feature extraction on unknown DLLs to determine a "Malicious Probability Score."

---

## Discord Integration

The legacy PHP backend has been deprecated in favor of **Discord Webhooks**, offering real-time notifications without the need for a web server.

- **Automated Alerts:** Detection logs appear instantly in your staff-only Discord channels.
- **Rich Embeds:** Logs include formatted data, including the offender's HWID and the specific AI detection trigger.
- **No Hosting Required:** Reduces infrastructure costs and setup complexity.

---

## Installation

### Client-Side (C++)
**Prerequisites:**
- Visual Studio 2022 (C++17 or higher recommended).
- Windows SDK.
- **MinHook** library.

**Core Files:**
- `dll_detector.cpp/h`: Hooking logic and AI inference integration.
- `logger.cpp/h`: Discord Webhook communication and XOR encryption.
- `ai_model_data.h`: Exported features and weights from the Python trainer.
- `hwidwin.h`: Hardware identification utilities.

### AI Training (Python)
**Prerequisites:**
- Python 3.9+.
- `scikit-learn`, `pefile`, and `pandas`.

---

## Configuration

1.  **Discord Setup:** Create a Webhook in your Discord Server Settings and paste the URL into `logger.h`:
    ```cpp
    #define DISCORD_WEBHOOK_URL "YOUR_WEBHOOK_URL_HERE"
    ```
2.  **AI Threshold:** Adjust the sensitivity of the AI detection in `dll_detector.h` to prevent false positives.
3.  **Whitelist:** Add custom game dependencies to the `whitelisted_modules` vector.

---

## Security Features

- **Anti-Debugging:** Basic checks to ensure the detector itself isn't being tampered with.
- **Payload Obfuscation:** XOR encryption prevents users from intercepting and reading the logs being sent to Discord.
- **Static Analysis:** The AI engine catches "Zero-Day" cheats that have been renamed or repacked to bypass string-based filters.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
