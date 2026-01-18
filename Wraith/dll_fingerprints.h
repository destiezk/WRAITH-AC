// dll_fingerprints.h - Whitelist of trusted DLL signatures
#pragma once
#include "main.h"
#include <string>
#include <vector>
#include <cmath>

// Fingerprint signature for a known trusted DLL
struct DllFingerprint {
    std::string name;           // DLL filename (case-insensitive)
    float fileSize;             // File size in bytes
    float numSections;          // Number of PE sections
    float numImports;           // Number of imported functions
    float numExports;           // Number of exported functions
    float entryPointRVA;        // Entry point relative virtual address
    float imageBase;            // Preferred load address
    float hasDebugInfo;         // Debug info present (1.0 = yes, 0.0 = no)
    float hasTLS;               // Thread local storage present (1.0 = yes, 0.0 = no)
    float suspiciousAPICount;   // Count of potentially suspicious APIs
    float entropy;              // Shannon entropy value
    float tolerance;            // Allowed deviation percentage (e.g., 0.01 = 1%)
};

// Whitelist of verified safe DLLs with exact signatures
static const std::vector<DllFingerprint> TRUSTED_DLL_FINGERPRINTS = {
    // sensfix.asi - Sensitivity fix mod
    {
        "sensfix.asi",
        158720.0f,      // fileSize
        5.0f,           // numSections
        2.0f,           // numImports
        0.0f,           // numExports
        39761.0f,       // entryPointRVA
        2.68435e+08f,   // imageBase
        1.0f,           // hasDebugInfo
        0.0f,           // hasTLS
        3.0f,           // suspiciousAPICount
        6.11311f,       // entropy
        0.01f           // 1% tolerance
    },

    // vorbisfile.dll - Audio codec library
    {
        "vorbisfile.dll",
        53760.0f,
        4.0f,
        1.0f,
        8.0f,
        6667.0f,
        2.68435e+08f,
        0.0f,
        0.0f,
        4.0f,
        6.20513f,
        0.01f
    },

    // Y-Axis_Sensitivity_Fix_gta3vcsa.asi - Y-axis sensitivity fix
    {
        "Y-Axis_Sensitivity_Fix_gta3vcsa.asi",
        71680.0f,
        5.0f,
        1.0f,
        0.0f,
        6360.0f,
        2.68435e+08f,
        1.0f,
        0.0f,
        2.0f,
        6.18435f,
        0.01f
    },

    // RefreshRateFixByDarkP1xel32.asi - Refresh rate fix (lowercase)
    {
        "RefreshRateFixByDarkP1xel32.asi",
        75264.0f,
        3.0f,
        1.0f,
        0.0f,
        201376.0f,
        2.68435e+08f,
        0.0f,
        0.0f,
        3.0f,
        7.73947,
        0.01f
    },

    // RefreshRateFixByDarkP1xel32.ASI - Refresh rate fix (uppercase)
    {
        "RefreshRateFixByDarkP1xel32.ASI",
        75264.0f,
        3.0f,
        1.0f,
        0.0f,
        201376.0f,
        2.68435e+08f,
        0.0f,
        0.0f,
        3.0f,
        7.73947,
        0.01f
    },

    // FramerateVigilante.SA.asi - Framerate fix
    {
       "FramerateVigilante.SA.asi",
        255488.0f,
        5.0f,
        1.0f,
        0.0f,
        54844.0f,
        2.68435e+08f,
        1.0f,
        0.0f,
        2.0f,
        6.1502,
        0.01f
    },

    // sensfix XY.asi - XY sensitivity fix
    {
        "sensfix XY.asi",
        71680.0f,
        5.0f,
        1.0f,
        0.0f,
        6360.0f,
        2.68435e+08f,
        1.0f,
        0.0f,
        2.0f,
        6.1843,
        0.01f
    },

    // PreciseFramerateLimiter.asi - Frame limiter
    {
        "PreciseFramerateLimiter.asi",
        212992.0f,
        5.0f,
        2.0f,
        0.0f,
        48963.0f,
        2.68435e+08f,
        1.0f,
        1.0f,
        2.0f,
        6.00516,
        0.01f
    },

    // SilentPatchSA.asi - Community patch
    {
        "SilentPatchSA.asi",
        282624.0f,
        5.0f,
        2.0f,
        4.0f,
        137312.0f,
        2.68435e+08f,
        1.0f,
        0.0f,
        3.0f,
        6.10715,
        0.01f
    }
};

// Check if a feature value matches expected value within tolerance
inline bool MatchesFingerprint(const DllFeatures& features, const DllFingerprint& fp) {
    // Helper: check if value is within tolerance range
    auto withinTolerance = [](float value, float expected, float tolerance) {
        return std::abs(value - expected) <= (expected * tolerance);
        };

    // Compare all features - must match within tolerance
    return withinTolerance(features.fileSize, fp.fileSize, fp.tolerance) &&
        withinTolerance(features.numSections, fp.numSections, fp.tolerance) &&
        withinTolerance(features.numImports, fp.numImports, fp.tolerance) &&
        withinTolerance(features.numExports, fp.numExports, fp.tolerance) &&
        withinTolerance(features.entryPointRVA, fp.entryPointRVA, fp.tolerance) &&
        withinTolerance(features.imageBase, fp.imageBase, fp.tolerance) &&
        features.hasDebugInfo == fp.hasDebugInfo &&
        features.hasTLS == fp.hasTLS &&
        withinTolerance(features.suspiciousAPICount, fp.suspiciousAPICount, fp.tolerance) &&
        withinTolerance(features.entropy, fp.entropy, fp.tolerance);
}

// Check if a DLL matches any trusted fingerprint
inline bool IsTrustedByFingerprint(const std::string& filename, const DllFeatures& features) {
    // Convert filename to lowercase for comparison
    std::string lowerName = filename;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

    // Check against all trusted fingerprints
    for (const auto& fp : TRUSTED_DLL_FINGERPRINTS) {
        std::string fpNameLower = fp.name;
        std::transform(fpNameLower.begin(), fpNameLower.end(), fpNameLower.begin(), ::tolower);

        // If filename matches, verify fingerprint
        if (lowerName.find(fpNameLower) != std::string::npos) {
            if (MatchesFingerprint(features, fp)) {
                return true;  // Verified trusted DLL
            }
        }
    }

    return false;  // No matching fingerprint found
}