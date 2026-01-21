# Wraith AntiCheat Client for GTA:SA:MP

A high‑performance anti‑cheat client for GTA:SA:MP (SAMP) focused on detecting unauthorized DLL injections, suspicious memory regions, and malicious processes in real time. The system combines traditional hook‑based detection with a C++17 inference engine running ONNX machine learning models against loaded modules and in‑memory artifacts.

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

- **Machine Learning Inference**  
  Uses an ONNX model (e.g. `dll_detector.onnx`) to classify DLLs and modules based on static structural features such as PE metadata and section statistics. 

- **Real‑time API Hooking**  
  Intercepts critical loading APIs (e.g. `LoadLibraryA/W` family) via a hooking library (such as Detours) to inspect every newly loaded module before it executes. 

- **SAMP / RakClient Integration**  
  Tailored for GTA:SA:MP multiplayer environments with support for RakClient and game‑specific RPC handlers for reporting and control.

- **Discord Webhook Reporting**  
  Sends structured, optionally obfuscated detection reports directly to Discord channels using webhook endpoints, avoiding the need for a custom backend.

- **Memory Region Monitoring**  
  Takes a baseline snapshot of process memory regions at startup and flags newly created, large executable private regions that typically indicate manual‑mapped DLLs or injected shellcode.

- **Process & Module Scanning**  
  Periodically iterates through modules in the game process to detect hidden, unlinked, or suspiciously modified components.

- **Hardware Fingerprinting**  
  Generates a stable HWID based on system properties to identify and track repeat offenders across accounts and sessions.

---

## Project Structure

The project is organized as a modular C++17 codebase.

### Header Files (`/include`)

- `ai_dll_detector.h` – Core logic for loading and running the ONNX model and applying thresholds.
- `dll_feature_extractor.h` – Extracts PE headers, section data, imports/exports, and entropy features for model input.
- `memory_scanner.h` – Implements baseline and runtime memory region tracking (new executable region detection).
- `process_scanner.h` – Utilities for enumerating processes and modules visible to the client.
- `webhook_sender.h` / `Discord.h` – Abstractions for sending formatted embeds and payloads to Discord webhooks.
- `samp.h` / `RakClient.h` – Game‑specific integration for GTA:SA:MP networking and events.
- `hwidwin.h` – Windows‑specific hardware ID generation helpers.
- `secure.h` – Simple encryption/obfuscation helpers (e.g. XOR encoding for sensitive strings).

### Source Files (`/src`)

- `dll_detector.cpp` – Main detection controller, hook setup/teardown, and orchestration of the pipeline.
- `dll_feature_extractor.cpp` – Implementation of PE parsing and feature vector construction.
- `ai_dll_detector.cpp` – ONNX Runtime integration and scoring logic.
- `memory_scanner.cpp` – Snapshot creation and periodic scanning for new executable private regions.
- `process_scanner.cpp` – Implementation of process and module scanning routines.
- `rpc_handlers.cpp` – Client RPC handling for server‑side integration and responses.
- `webhook_sender.cpp` / `Discord.cpp` – Discord webhook formatting, serialization, and sending.
- `hwidwin.cpp` – HWID collection and normalization.
- `secure.cpp` – Runtime decoding and small security helpers.

### Resources & Assets

- `dll_detector.onnx` – Trained neural network model used for static DLL/module classification.
- `detours.lib` / `detours.h` – Hooking library used to intercept `LoadLibrary` and related APIs.
- Optional config (e.g. `config.json`) – Centralized configuration for thresholds, webhook URLs, and feature toggles.

---

## How It Works

### Detection Pipeline

1. **Initialization**  
   - On injection/start, the client initializes the ONNX runtime, loads the model, and installs hooks on module loading APIs.  
   - A memory baseline is taken: the entire virtual address space of the process is walked and all existing regions are stored as trusted. 

2. **Event Interception**  
   - When a DLL is loaded through hooked APIs, the file is passed to the feature extractor for PE‑level analysis.  
   - In parallel, a background thread periodically rescans memory and checks for newly created regions that do not exist in the baseline.

3. **Feature Extraction & Inference**  
   - The feature extractor builds a fixed‑size vector from PE metadata, section entropy, imports, and exports.  
   - The AI detector feeds this vector into the ONNX model and receives a maliciousness score.

4. **Decision & Response**  
   - If the AI score exceeds the configurable threshold, or a new **large, executable, private** memory region appears, the client:  
     - Serializes context (timestamp, HWID, DLL name or region address/size).  
     - Sends a Discord webhook embed describing the event.  
     - Optionally terminates the game client, triggers a kick, or flags the account.

### Memory Region Monitoring

- A snapshot of all memory regions (base address + size) is recorded once the game and anti‑cheat are fully initialized. 
- Every few seconds, the scanner walks memory again; any region not present in the snapshot is considered “new.”  
- Only new regions that are **private, committed, executable, and larger than a safe threshold** (e.g. 64 KB) are treated as highly suspicious, which strongly correlates with manual‑mapped DLLs or large injected code buffers.

---

## AI Architecture

- **Training Pipeline**  
  - A dataset of clean and malicious DLLs is processed offline to extract PE‑level features (header fields, number of sections, import density, entropy, etc.).  
  - The resulting feature matrix and labels are used to train a classifier, which is then exported to the ONNX format.

- **Model & Runtime**  
  - The client loads the ONNX file at startup and constructs an inference session through ONNX Runtime.  
  - For each candidate module, a feature tensor is built and run through the model to obtain a probability score.  
  - Threshold values can be tuned to tighten or relax detection sensitivity, depending on how aggressive the deployment should be.

---

## Discord Integration

- **Webhook‑based Logging**  
  - Detection events are converted into JSON‑like payloads that include core metadata (player, HWID, module name, score, region address/size).  
  - Payloads are sent to a configured Discord webhook URL, allowing staff to monitor detections without managing their own web backend.

- **Rich Embeds**  
  - Messages can include colored embeds, detailed fields, and short descriptions summarizing why the module or memory region was flagged.

- **Light Obfuscation**  
  - Webhook URLs and other sensitive strings can be lightly encoded (e.g. XOR) and decoded at runtime to raise the bar slightly against static analysis.

---

## Installation

### Prerequisites

- Visual Studio 2022 (or newer) with C++17 support enabled.  
- Windows SDK matching your target OS.  
- GTA:SA:MP client and, optionally, RakClient headers/libs for deeper integration.  
- ONNX Runtime binaries and headers configured for your target architecture.  
- Detours (or another hooking library) properly linked.

### Build Instructions

1. Clone the repository and open the solution in Visual Studio.  
2. Configure include and library paths for ONNX Runtime, Detours, and SAMP/RakClient dependencies.  
3. Link the hooking library (e.g. `detours.lib`) in the linker settings.  
4. Place `dll_detector.onnx` in the game directory or adjust the loading path in the code.  
5. Build the project in **Release** mode for the architecture used by GTA:SA:MP (typically x86).

---

## Configuration

- **Discord Webhook**  
  - Create a webhook in your Discord server and paste its URL into the appropriate header or configuration file (e.g. `webhook_sender.h` or `config.json`).  

- **Model & Paths**  
  - Ensure the ONNX model file is shipped with the client and that the path used in `ai_dll_detector` matches your deployment layout.  

- **Detection Thresholds**  
  - Tune the AI score threshold to find a good balance between detection rate and false positives.  
  - Optionally expose toggles for enabling/disabling memory region monitoring, process scanning, or stricter modes.

- **Game Integration**  
  - Configure server‑side logic to react to client reports (kicks, bans, logging) using the RPC handlers integrated via `samp.h` / `RakClient.h`.

---

## Security Features

- **String / Config Obfuscation**  
  - Sensitive constants (webhooks, API keys, internal identifiers) are stored in encoded form and decoded at runtime to frustrate basic static inspection.

- **Hook Integrity Checks**  
  - Periodic verification that API hooks are still installed correctly and haven’t been unhooked or patched by external tools.

- **Encrypted / Masked Reports**  
  - Simple XOR or similar schemes can be applied to outgoing payloads before they are sent to Discord, making captured traffic less human‑readable.

- **Baseline‑based Memory Defense**  
  - New, large executable private regions are treated as strong indicators of manual mapping or runtime code injection, complementing API‑level hook detection. 

---

## License

This project is distributed under the MIT License. See the `LICENSE` file for complete terms and conditions.
