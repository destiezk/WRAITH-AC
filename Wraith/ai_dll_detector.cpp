// ai_dll_detector.cpp 
#include "main.h"
#include "ai_dll_detector.h"
#include "dll_feature_extractor.h"
#include "dll_fingerprints.h"
#include "resource.h"
#include <iostream>
#include <windows.h>
#include <filesystem>

// global module instance from main.cpp
extern HINSTANCE g_hInstance;

// confidence threshold for malicious classification (99.95%)
static const float DETECTION_THRESHOLD = 0.9995f;

AIDllDetector::AIDllDetector()
    : m_lastConfidence(0.0f), m_initialized(false) {
}

AIDllDetector::~AIDllDetector() {
}

// load the ONNX model from embedded resource
bool AIDllDetector::InitializeFromResource() {
    try {
        std::cout << "[AI] Attempting to load model from embedded resource..." << std::endl;

        // Get module handle
        HMODULE hModule = g_hInstance;
        if (!hModule) {
            std::cerr << "[AI] ERROR: g_hInstance is NULL! Make sure it's set in DllMain." << std::endl;
            return false;
        }

        std::cout << "[AI] Module handle: " << hModule << std::endl;

        // find the model resource
        HRSRC hRes = FindResource(hModule, MAKEINTRESOURCE(IDR_AI_MODEL), RT_RCDATA);
        if (!hRes) {
            DWORD error = GetLastError();
            std::cerr << "[AI] ERROR: FindResource failed! Error code: " << error << std::endl;
            return false;
        }

        std::cout << "[AI] Resource found!" << std::endl;

        // load the resource into memory
        HGLOBAL hData = LoadResource(hModule, hRes);
        if (!hData) {
            std::cerr << "[AI] ERROR: LoadResource failed!" << std::endl;
            return false;
        }

        // get pointer to model data
        void* pModelData = LockResource(hData);
        DWORD modelSize = SizeofResource(hModule, hRes);

        std::cout << "[AI] Model size: " << modelSize << " bytes" << std::endl;

        if (!pModelData || modelSize == 0) {
            std::cerr << "[AI] ERROR: Invalid model data!" << std::endl;
            return false;
        }

        // initialize ONNX Runtime environment
        m_env = std::make_unique<Ort::Env>(ORT_LOGGING_LEVEL_WARNING, "DllDetector");

        // configure session options
        Ort::SessionOptions sessionOptions;
        sessionOptions.SetIntraOpNumThreads(1);
        sessionOptions.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_BASIC);

        // create inference session from memory
        m_session = std::make_unique<Ort::Session>(*m_env, pModelData, modelSize, sessionOptions);

        m_initialized = true;
        std::cout << "[AI] ? Model loaded successfully from embedded resource!" << std::endl;
        return true;
    }
    catch (const Ort::Exception& e) {
        std::cerr << "[AI] ONNX Runtime error: " << e.what() << std::endl;
        m_initialized = false;
        return false;
    }
    catch (const std::exception& e) {
        std::cerr << "[AI] Exception: " << e.what() << std::endl;
        m_initialized = false;
        return false;
    }
    catch (...) {
        std::cerr << "[AI] Unknown error loading model" << std::endl;
        m_initialized = false;
        return false;
    }
}

// analyze a DLL and determine if it's suspicious
bool AIDllDetector::IsSuspicious(const std::string& dllPath) {
    if (!m_initialized) {
        std::cerr << "[AI] Model not initialized!" << std::endl;
        return false;
    }

    try {
        // extract features from the DLL
        DllFeatures features = DllFeatureExtractor::ExtractFeatures(dllPath);

        // Get filename for fingerprint check
        std::filesystem::path p(dllPath);
        std::string filename = p.filename().string();

        // check if DLL matches trusted fingerprint
        if (IsTrustedByFingerprint(filename, features)) {
            std::cout << "[FINGERPRINT] " << filename << " matches trusted signature - ALLOWED" << std::endl;
            m_lastConfidence = 0.0f;
            return false;
        }

        // debug: Print raw features
        std::cout << "[DEBUG] Raw features for: " << dllPath << std::endl;
        std::cout << "  fileSize: " << features.fileSize << std::endl;
        std::cout << "  numSections: " << features.numSections << std::endl;
        std::cout << "  numImports: " << features.numImports << std::endl;
        std::cout << "  numExports: " << features.numExports << std::endl;
        std::cout << "  entryPointRVA: " << features.entryPointRVA << std::endl;
        std::cout << "  imageBase: " << features.imageBase << std::endl;
        std::cout << "  hasDebugInfo: " << features.hasDebugInfo << std::endl;
        std::cout << "  hasTLS: " << features.hasTLS << std::endl;
        std::cout << "  suspiciousAPICount: " << features.suspiciousAPICount << std::endl;
        std::cout << "  entropy: " << features.entropy << std::endl;

        // normalize features for model input
        std::vector<float> inputData = {
            features.fileSize / 10000000.0f,
            features.numSections / 10.0f,
            features.numImports / 100.0f,
            features.numExports / 100.0f,
            features.entryPointRVA / 1000000.0f,
            features.imageBase / 4294967295.0f,
            static_cast<float>(features.hasDebugInfo),
            static_cast<float>(features.hasTLS),
            features.suspiciousAPICount / 10.0f,
            features.entropy / 8.0f
        };

        // debug: print normalized features
        std::cout << "[DEBUG] Normalized features:" << std::endl;
        std::cout << "  [" << inputData[0] << ", " << inputData[1] << ", " << inputData[2] << ", "
            << inputData[3] << ", " << inputData[4] << ", " << inputData[5] << ", "
            << inputData[6] << ", " << inputData[7] << ", " << inputData[8] << ", "
            << inputData[9] << "]" << std::endl;

        // create input tensor
        std::vector<int64_t> inputShape = { 1, 10 };
        auto memoryInfo = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
        Ort::Value inputTensor = Ort::Value::CreateTensor<float>(
            memoryInfo, inputData.data(), inputData.size(),
            inputShape.data(), inputShape.size());

        // define input/output names
        const char* inputNames[] = { "float_input" };
        const char* outputNames[] = { "label", "probabilities" };

        // run inference
        auto outputTensors = m_session->Run(
            Ort::RunOptions{ nullptr },
            inputNames, &inputTensor, 1,
            outputNames, 2);

        // get prediction results
        int64_t* prediction = outputTensors[0].GetTensorMutableData<int64_t>();
        float* probabilities = outputTensors[1].GetTensorMutableData<float>();

        // store confidence score (probability of being malicious)
        m_lastConfidence = probabilities[1];
        std::cout << "[DEBUG] Probabilities: [" << probabilities[0] << ", " << probabilities[1] << "]" << std::endl;

        // check if confidence exceeds threshold
        bool isSuspicious = (m_lastConfidence >= DETECTION_THRESHOLD);

        std::cout << "[AI] DLL: " << dllPath << " | Prediction: "
            << (isSuspicious ? "SUSPICIOUS" : "CLEAN")
            << " | Confidence: " << (m_lastConfidence * 100.0f) << "%"
            << " | Threshold: " << (DETECTION_THRESHOLD * 100.0f) << "%" << std::endl;

        return isSuspicious;
    }
    catch (const Ort::Exception& e) {
        std::cerr << "[AI] Inference error: " << e.what() << std::endl;
        return false;
    }
    catch (...) {
        std::cerr << "[AI] Unknown error during inference" << std::endl;
        return false;
    }
}

// get the confidence score from last prediction
float AIDllDetector::GetLastConfidence() const {
    return m_lastConfidence;
}
