// dll_fingerprints.h - SECURE FINGERPRINT WHITELIST
#pragma once
#include "main.h"
#include <string>
#include <vector>
#include <cmath>

// Structure to hold DLL fingerprint
struct DllFingerprint {
    std::string name;           // Filename (case-insensitive)
    float fileSize;
    float numSections;
    float numImports;
    float numExports;
    float entryPointRVA;
    float imageBase;
    float hasDebugInfo;
    float hasTLS;
    float suspiciousAPICount;
    float entropy;
    float tolerance;            // How much deviation to allow (e.g., 0.01 = 1%)
};

// Whitelist of known good DLLs with their exact signatures
static const std::vector<DllFingerprint> TRUSTED_DLL_FINGERPRINTS = {
    // sensfix.asi
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

    // vorbisfile.dll
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

    // Y-Axis_Sensitivity_Fix_gta3vcsa.asi.dll
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
    },

    // Add more trusted DLLs here with their exact features
};

// Check if features match a fingerprint within tolerance
inline bool MatchesFingerprint(const DllFeatures& features, const DllFingerprint& fp) {
    auto withinTolerance = [](float value, float expected, float tolerance) {
        return std::abs(value - expected) <= (expected * tolerance);
        };

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

// Check if a DLL is trusted by fingerprint
inline bool IsTrustedByFingerprint(const std::string& filename, const DllFeatures& features) {
    std::string lowerName = filename;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

    for (const auto& fp : TRUSTED_DLL_FINGERPRINTS) {
        std::string fpNameLower = fp.name;
        std::transform(fpNameLower.begin(), fpNameLower.end(), fpNameLower.begin(), ::tolower);

        if (lowerName.find(fpNameLower) != std::string::npos) {
            if (MatchesFingerprint(features, fp)) {
                return true;  // Exact match!
            }
        }
    }

    return false;  // No fingerprint match
}
