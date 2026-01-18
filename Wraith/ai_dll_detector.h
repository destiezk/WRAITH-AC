// ai_dll_detector.h - AI DLL detector
#pragma once
#include <string>
#include <memory>
#include <vector>
#include "onnxruntime_cxx_api.h"
#include "dll_feature_extractor.h"

class AIDllDetector {
public:
    // Create/destroy detector
    AIDllDetector();
    ~AIDllDetector();

    // Load AI model from resource
    bool InitializeFromResource();

    // Check if a DLL is suspicious
    bool IsSuspicious(const std::string& dllPath);

    // Get confidence of last check
    float GetLastConfidence() const;

private:
    // Convert raw features to model input
    std::vector<float> NormalizeFeatures(const DllFeatures& features);

    std::unique_ptr<Ort::Env> m_env;          // ONNX runtime environment
    std::unique_ptr<Ort::Session> m_session;  // Loaded ONNX model session
    DllFeatureExtractor m_featureExtractor;   // Extracts DLL features
    bool m_initialized;                       // True when model is ready
    float m_lastConfidence;                   // Last prediction confidence
};
