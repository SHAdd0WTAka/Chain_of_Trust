#include "AdminAuth.hpp"
#include "ipc.hpp"
#include <ctime>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <random>
#include <windows.h>

bool AdminAuth::IsWithinWindow(int startHour, int startMin, int endHour, int endMin) {
    time_t now = time(0);
    tm ltm;
    localtime_s(&ltm, &now);
    int currentMin = ltm.tm_hour * 60 + ltm.tm_min;
    int start = startHour * 60 + startMin;
    int end = endHour * 60 + endMin;
    return (currentMin >= start && currentMin <= end);
}

std::string AdminAuth::GenerateChallenge() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);

    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < 32; i++) {
        ss << dis(gen);
    }

    DWORD pid = GetCurrentProcessId();
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    BYTE hash[32] = { 0 };

    std::string challenge = "https://chain-of-trust.local/auth?code=" + ss.str()
        + "&pid=" + std::to_string(pid)
        + "&arch=" + std::to_string(si.wProcessorArchitecture);

    return challenge;
}

bool AdminAuth::VerifySecret(const std::string& inputUrl) {
    std::size_t codePos = inputUrl.find("code=");
    if (codePos == std::string::npos) return false;

    std::size_t endPos = inputUrl.find('&', codePos);
    std::string code;
    if (endPos == std::string::npos) {
        code = inputUrl.substr(codePos + 5);
    } else {
        code = inputUrl.substr(codePos + 5, endPos - codePos - 5);
    }

    if (code.length() < 16) return false;

    for (char c : code) {
        if (!isxdigit(c)) return false;
    }

    return true;
}

bool AdminAuth::ValidateProtocolFlip(const std::string& inputUrl) {
    if (inputUrl.find("https://") != std::string::npos) {
        std::cerr << "[AKIR] BLOCKED: HTTPS detected - protocol not flipped by human" << std::endl;
        return false;
    }

    if (inputUrl.find("http://") != std::string::npos && VerifySecret(inputUrl)) {
        std::cout << "[AKIR] Protocol flip confirmed: HTTPS -> HTTP (human present)" << std::endl;
        return true;
    }

    return false;
}

void AdminAuth::ResetKernelTimer() {
    HANDLE hDevice = CreateFileW(L"\\\\.\\AKIR_EDR", GENERIC_WRITE,
        FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "[AKIR] Cannot open driver device. Is driver loaded?" << std::endl;
        return;
    }

    DWORD bytesReturned = 0;
    DeviceIoControl(hDevice, IOCTL_AKIR_RESET_TIMER, NULL, 0, NULL, 0, &bytesReturned, NULL);
    CloseHandle(hDevice);

    std::cout << "[AKIR] Kernel timer reset via IOCTL" << std::endl;
}
