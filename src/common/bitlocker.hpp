#pragma once
#include <windows.h>
#include <wbemidl.h>
#include <string>
#include <vector>

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
    static bool Initialize();
    static void Shutdown();
    static bool IsAvailable();

    static std::vector<BitLockerDrive> EnumerateDrives();
    static std::vector<BitLockerKey> GetKeyProtectors(const std::wstring& driveLetter);
    static bool GetKeyProtectorData(const std::wstring& driveLetter, const std::wstring& protectorId, BitLockerKey& key);
    static bool SetNumericalPassword(const std::wstring& driveLetter, const std::wstring& password);
    static std::wstring GetLastError();

private:
    static IWbemServices* m_pServices;
    static bool m_initialized;
    static std::wstring m_lastError;

    static bool ConnectWmi();
    static IEnumWbemClassObject* Query(const std::wstring& query);
    static IWbemClassObject* GetObject(const std::wstring& path);
    static IWbemClassObject* ExecMethod(const std::wstring& objPath, const std::wstring& method,
                                        IWbemClassObject* pIn);
};
