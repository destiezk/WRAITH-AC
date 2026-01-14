// ai_dll_detector.h - COMPLETE WITH FINGERPRINTS
#pragma once
#include <string>
#include <memory>
#include <vector>
#include "onnxruntime_cxx_api.h"
#include "dll_feature_extractor.h"

class AIDllDetector {
public:
    AIDllDetector();
    ~AIDllDetector();

    // Initialize the model from file
    bool InitializeFromResource();

    // Check if a DLL is suspicious
    bool IsSuspicious(const std::string& dllPath);

    // Get the confidence score from the last prediction
    float GetLastConfidence() const;

private:
    // *** ADD THESE ***
    std::vector<float> NormalizeFeatures(const DllFeatures& features);

    std::unique_ptr<Ort::Env> m_env;
    std::unique_ptr<Ort::Session> m_session;
    DllFeatureExtractor m_featureExtractor;  // *** ADD THIS ***
    bool m_initialized;
    float m_lastConfidence;
};