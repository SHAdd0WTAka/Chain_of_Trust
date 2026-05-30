#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_DCOM
#define _WIN32_DCOM
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#include <wbemidl.h>
#include <string>
#include <vector>
#include <mutex>

struct BitLockerDrive {
    std::wstring DriveLetter;
    DWORD ProtectionStatus;
    std::wstring ConversionStatus;
    std::vector<std::wstring> KeyProtectorIds;
};

struct BitLockerKey {
    std::wstring ProtectorId;
    std::wstring ProtectorType;
    std::vector<BYTE> KeyData;
    std::wstring NumericalPassword;
};

class BitLockerManager {
public:
    [[nodiscard]] static bool Initialize();
    static void Shutdown();
    [[nodiscard]] static bool IsAvailable() noexcept;

    [[nodiscard]] static std::vector<BitLockerDrive> EnumerateDrives();
    [[nodiscard]] static std::vector<BitLockerKey> GetKeyProtectors(const std::wstring& driveLetter);
    [[nodiscard]] static bool GetKeyProtectorData(const std::wstring& driveLetter, const std::wstring& protectorId, BitLockerKey& key);
    [[nodiscard]] static bool SetNumericalPassword(const std::wstring& driveLetter, const std::wstring& password);
    [[nodiscard]] static std::wstring GetLastError() noexcept;

private:
    static IWbemServices* m_pServices;
    static bool m_initialized;
    static std::wstring m_lastError;

    [[nodiscard]] static bool ConnectWmi();
    [[nodiscard]] static IEnumWbemClassObject* Query(const std::wstring& query);
    [[nodiscard]] static IWbemClassObject* GetObject(const std::wstring& path);
    [[nodiscard]] static IWbemClassObject* ExecMethod(const std::wstring& objPath, const std::wstring& method,
                                        IWbemClassObject* pIn);
    static std::mutex m_mutex;
};
