#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>

struct ServiceStatus {
    bool IsInstalled;
    bool IsRunning;
    DWORD State;
    std::wstring DisplayName;
    std::wstring BinaryPath;
};

class ServiceManager {
public:
    static bool Install(const std::wstring& serviceName, const std::wstring& displayName,
                        const std::wstring& binaryPath);
    static bool Uninstall(const std::wstring& serviceName);
    static bool Start(const std::wstring& serviceName);
    static bool Stop(const std::wstring& serviceName);
    static bool Restart(const std::wstring& serviceName);
    static ServiceStatus Query(const std::wstring& serviceName);
    static bool SetRecoveryActions(const std::wstring& serviceName);

private:
    static SC_HANDLE OpenScm(DWORD access);
    static std::wstring GetLastErrorMsg();
};
