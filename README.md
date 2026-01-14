# Wraith AntiCheat built for GTA:SA:MP

A high-performance anti-cheat solution designed for game environments (SAMP/RakClient) that detects and reports unauthorized DLL injections in real time. This system utilizes a C++ inference engine to run ONNX machine learning models against suspicious modules.

---

## Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
- [AI Architecture](#ai-architecture)
- [Discord Integration](#discord-integration)
- [Installation](#installation)
- [Configuration](#configuration)
- [Security Features](#security-features)
- [License](#license)

---

## Features

- **Machine Learning Inference:** Uses `dll_detector.onnx` to classify DLLs based on structural features.
- **Real-time API Hooking:** Utilizes Microsoft Detours to intercept `LoadLibrary` calls.
- **SAMP/RakClient Integration:** Tailored for multiplayer environments with specialized RPC handlers.
- **Discord Webhook Reporting:** Encrypted, real-time logging sent directly to Discord channels.
- **Memory & Process Scanning:** Scans active process memory to catch hidden or manual-mapped modules.
- **Hardware Fingerprinting:** Unique HWID generation to track offenders across multiple accounts.

---

## Project Structure

The project is organized into a modular C++ architecture:

### Header Files (`/include`)
- **`ai_dll_detector.h`**: Core logic for the AI inference engine.
- **`dll_feature_extractor.h`**: Extracts PE headers and entropy for model input.
- **`webhook_sender.h` & `Discord.h`**: Manages Discord API communication.
- **`samp.h` & `RakClient.h`**: Integration headers for game-specific logic.
- **`hwidwin.h`**: Hardware ID generation utilities.
- **`secure.h`**: XOR encryption and security obfuscation.

### Source Files (`/src`)
- **`process_scanner.cpp`**: Logic for iterating through loaded modules and memory regions.
- **`rpc_handlers.cpp`**: Manages remote procedure calls for server-client synchronization.
- **`dll_detector.cpp`**: The primary detection loop and hooking implementation.
- **`memory.cpp`**: Low-level memory manipulation and protection checks.

### Resources & Assets
- **`dll_detector.onnx`**: The trained Machine Learning model used for detection.
- **`detours.lib`**: Microsoft Detours library for function hooking.

---

## How It Works

### 1. The Detection Pipeline
* **Initialization:** Upon `main.cpp` execution, the system loads the `dll_detector.onnx` model and installs hooks on `LoadLibrary` using `detours.h`.
* **Feature Extraction:** When a DLL is loaded, `dll_feature_extractor.cpp` analyzes the file's PE sections, import tables, and entropy.
* **Inference:** The data is passed to `ai_dll_detector.cpp`, which runs the ONNX model to determine a maliciousness score.
* **Action:** If the score exceeds the threshold, `webhook_sender.cpp` dispatches an encrypted report, and the game is terminated.

### 2. Networking & Logging
The system uses `Discord.cpp` and `webhook_sender.cpp` to bypass the need for a traditional web server. All logs are:
1.  Serialized with local metadata (Timestamp, HWID, DLL Name).
2.  Posted to a Discord Webhook.
---

## AI Architecture

The system utilizes a **Static Analysis** approach:
* **Training:** Features were extracted from a dataset of 5,000+ clean and malicious DLLs using a Python-based pre-processor.
* **Model:** The resulting model was exported to **ONNX (Open Neural Network Exchange)** format for high-performance C++ inference.
* **Input Features:** PE Header metadata, Number of Exports, Section Entropy, and Import Density.

---

## Discord Integration

The system uses `Discord.cpp` and `webhook_sender.cpp` to bypass the need for a traditional web server. All logs are:
-   **Serialized** with local metadata (Timestamp, HWID, DLL Name).
-   **Posted** to a Discord Webhook as a formatted Rich Embed.

---

## Installation

### Prerequisites
- **Visual Studio 2022** (C++17 only).
- **Windows SDK**.
- **sampapi.lib**
- **ONNX Runtime** (to load and execute `dll_detector.onnx`).

### Build Instructions
1. Open the solution in Visual Studio.
2. Ensure `detours.lib` is properly linked in the project properties.
3. Set your Discord Webhook URL in `webhook_sender.h`.
4. Build in **Release x86/x64** (depending on your game architecture).

---

## Configuration

To set up the system for your server:
1.  **Discord:** Generate a Webhook URL and paste it into `webhook_sender.h`.
2.  **Model:** Ensure `dll_detector.onnx` is in the same directory as your game executable.
3.  **Thresholds:** Adjust detection sensitivity in `ai_dll_detector.h`.

---

## Security Features

- **String Obfuscation:** Critical strings and URLs are encrypted in `secure.h` to prevent static string analysis.
- **Hook Protection:** Monitors the integrity of Detours hooks to ensure they aren't unhooked by the cheat.
- **Encrypted Transmission:** All data sent via `webhook_sender` is XOR-masked to prevent packet sniffing.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
