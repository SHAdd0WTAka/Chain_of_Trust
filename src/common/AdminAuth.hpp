#pragma once
#include <string>

class AdminAuth {
public:
    static bool IsWithinWindow(int startHour, int startMin, int endHour, int endMin);
    static bool ValidateProtocolFlip(const std::string& inputUrl);
    static std::string GenerateChallenge();
    static bool VerifySecret(const std::string& inputUrl);
    static void ResetKernelTimer();
};
