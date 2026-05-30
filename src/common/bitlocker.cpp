#include "bitlocker.hpp"
#include <comdef.h>
#include <sstream>
#include <iomanip>
#include <mutex>

#pragma comment(lib, "wbemuuid.lib")

IWbemServices* BitLockerManager::m_pServices = nullptr;
bool BitLockerManager::m_initialized = false;
std::wstring BitLockerManager::m_lastError;
std::mutex BitLockerManager::m_mutex;

static std::wstring VariantToString(const VARIANT& vt) {
    if (vt.vt == VT_BSTR) return vt.bstrVal ? vt.bstrVal : L"";
    if (vt.vt == VT_I4) return std::to_wstring(vt.lVal);
    if (vt.vt == VT_UI4) return std::to_wstring(vt.ulVal);
    if (vt.vt == VT_BOOL) return vt.boolVal ? L"True" : L"False";
    return L"";
}

static std::wstring GetWmiError(HRESULT hr) {
    _com_error err(hr);
    return err.ErrorMessage();
}

bool BitLockerManager::Initialize() {
    if (m_initialized) return true;

    HRESULT hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastError = L"CoInitializeEx failed: " + GetWmiError(hr);
        return false;
    }

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL);
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastError = L"CoInitializeSecurity failed: " + GetWmiError(hr);
        return false;
    }

    if (!ConnectWmi()) return false;

    m_initialized = true;
    return true;
}

bool BitLockerManager::ConnectWmi() {
    IWbemLocator* pLoc = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, reinterpret_cast<LPVOID*>(&pLoc));
    if (FAILED(hr)) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastError = L"CoCreateInstance IWbemLocator failed: " + GetWmiError(hr);
        return false;
    }

    hr = pLoc->ConnectServer(L"ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption",
        NULL, NULL, NULL, 0, NULL, NULL, &m_pServices);
    pLoc->Release();

    if (FAILED(hr)) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastError = L"ConnectServer to BitLocker namespace failed: " + GetWmiError(hr);
        m_pServices = nullptr;
        return false;
    }

    hr = CoSetProxyBlanket(m_pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
        NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE);
    if (FAILED(hr)) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastError = L"CoSetProxyBlanket failed: " + GetWmiError(hr);
        m_pServices->Release();
        m_pServices = nullptr;
        return false;
    }

    return true;
}

void BitLockerManager::Shutdown() {
    if (m_pServices) {
        m_pServices->Release();
        m_pServices = nullptr;
    }
    CoUninitialize();
    m_initialized = false;
}

bool BitLockerManager::IsAvailable() noexcept {
    return m_initialized && m_pServices != nullptr;
}

IEnumWbemClassObject* BitLockerManager::Query(const std::wstring& query) {
    IEnumWbemClassObject* pEnum = nullptr;
    HRESULT hr = m_pServices->ExecQuery(L"WQL", bstr_t(query.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnum);
    if (FAILED(hr)) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastError = L"ExecQuery failed: " + GetWmiError(hr);
        return nullptr;
    }
    return pEnum;
}

IWbemClassObject* BitLockerManager::GetObject(const std::wstring& path) {
    IWbemClassObject* pObj = nullptr;
    HRESULT hr = m_pServices->GetObject(bstr_t(path.c_str()), 0, NULL, &pObj, NULL);
    if (FAILED(hr)) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastError = L"GetObject failed: " + GetWmiError(hr);
        return nullptr;
    }
    return pObj;
}

IWbemClassObject* BitLockerManager::ExecMethod(const std::wstring& objPath, const std::wstring& method,
    IWbemClassObject* pIn) {
    IWbemClassObject* pOut = nullptr;
    HRESULT hr = m_pServices->ExecMethod(bstr_t(objPath.c_str()),
        bstr_t(method.c_str()), 0, NULL, pIn, &pOut, NULL);
    if (FAILED(hr)) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastError = L"ExecMethod " + method + L" failed: " + GetWmiError(hr);
        return nullptr;
    }
    return pOut;
}

std::vector<BitLockerDrive> BitLockerManager::EnumerateDrives() {
    std::vector<BitLockerDrive> drives;

    IEnumWbemClassObject* pEnum = Query(L"SELECT * FROM Win32_EncryptableVolume");
    if (!pEnum) return drives;

    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == S_OK && pObj) {
        BitLockerDrive drive;
        VARIANT vt;

        if (pObj->Get(L"DriveLetter", 0, &vt, 0, 0) == S_OK) {
            drive.DriveLetter = VariantToString(vt);
            VariantClear(&vt);
        }

        if (pObj->Get(L"ProtectionStatus", 0, &vt, 0, 0) == S_OK) {
            drive.ProtectionStatus = vt.ulVal;
            VariantClear(&vt);
        }

        if (pObj->Get(L"ConversionStatus", 0, &vt, 0, 0) == S_OK) {
            drive.ConversionStatus = VariantToString(vt);
            VariantClear(&vt);
        }

        std::wstring objPath = L"Win32_EncryptableVolume.DriveLetter=\"" + drive.DriveLetter + L"\"";

        IWbemClassObject* pParams = nullptr;
        IWbemClassObject* pInClass = nullptr;
        HRESULT hr = m_pServices->GetObject(bstr_t((objPath + L"\\GetKeyProtectors").c_str()),
            0, NULL, &pInClass, NULL);
        if (SUCCEEDED(hr) && pInClass) {
            pInClass->SpawnInstance(0, &pParams);
            VARIANT vtType;
            vtType.vt = VT_UI4;
            vtType.ulVal = 0;
            pParams->Put(L"KeyProtectorType", 0, &vtType, 0);
            pInClass->Release();

            IWbemClassObject* pResult = ExecMethod(objPath, L"GetKeyProtectors", pParams);
            if (pResult) {
                VARIANT vtResult;
                if (pResult->Get(L"ProtectorIds", 0, &vtResult, 0, 0) == S_OK) {
                    if (vtResult.vt == (VT_ARRAY | VT_BSTR)) {
                        SAFEARRAY* pArray = vtResult.parray;
                        LONG lbound = 0, ubound = 0;
                        SafeArrayGetLBound(pArray, 1, &lbound);
                        SafeArrayGetUBound(pArray, 1, &ubound);
                        for (LONG i = lbound; i <= ubound; i++) {
                            BSTR bstrVal = nullptr;
                            SafeArrayGetElement(pArray, &i, &bstrVal);
                            if (bstrVal) {
                                drive.KeyProtectorIds.push_back(std::wstring(bstrVal));
                                SysFreeString(bstrVal);
                            }
                        }
                    }
                    VariantClear(&vtResult);
                }
                pResult->Release();
            }
            if (pParams) pParams->Release();
        }

        drives.push_back(drive);
        pObj->Release();
    }

    pEnum->Release();
    return drives;
}

std::vector<BitLockerKey> BitLockerManager::GetKeyProtectors(const std::wstring& driveLetter) {
    std::vector<BitLockerKey> keys;
    std::vector<BitLockerDrive> drives = EnumerateDrives();

    BitLockerDrive* target = nullptr;
    for (auto& d : drives) {
        if (d.DriveLetter == driveLetter) {
            target = &d;
            break;
        }
    }
    if (!target) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastError = L"Drive not found: " + driveLetter;
        return keys;
    }

    for (auto& pid : target->KeyProtectorIds) {
        BitLockerKey key;
        key.ProtectorId = pid;
        GetKeyProtectorData(driveLetter, pid, key);
        keys.push_back(key);
    }

    return keys;
}

bool BitLockerManager::GetKeyProtectorData(const std::wstring& driveLetter,
    const std::wstring& protectorId, BitLockerKey& key) {
    std::wstring objPath = L"Win32_EncryptableVolume.DriveLetter=\"" + driveLetter + L"\"";

    IWbemClassObject* pInClass = nullptr;
    HRESULT hr = m_pServices->GetObject(
        bstr_t((objPath + L"\\GetKeyProtectorKey").c_str()), 0, NULL, &pInClass, NULL);
    if (FAILED(hr) || !pInClass) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastError = L"GetKeyProtectorKey method not found";
        return false;
    }

    IWbemClassObject* pParams = nullptr;
    pInClass->SpawnInstance(0, &pParams);
    VARIANT vt;
    vt.vt = VT_BSTR;
    vt.bstrVal = SysAllocString(protectorId.c_str());
    pParams->Put(L"ProtectorId", 0, &vt, 0);
    VariantClear(&vt);
    pInClass->Release();

    IWbemClassObject* pResult = ExecMethod(objPath, L"GetKeyProtectorKey", pParams);
    if (pParams) pParams->Release();

    if (!pResult) return false;

    VARIANT vtType;
    if (pResult->Get(L"ProtectorType", 0, &vtType, 0, 0) == S_OK) {
        switch (vtType.ulVal) {
        case 3: key.ProtectorType = L"NumericalPassword"; break;
        case 2: key.ProtectorType = L"ExternalKey"; break;
        case 1: key.ProtectorType = L"TPM"; break;
        case 4: key.ProtectorType = L"TPMAndPIN"; break;
        default: key.ProtectorType = L"Other(" + std::to_wstring(vtType.ulVal) + L")"; break;
        }
        VariantClear(&vtType);
    }

    VARIANT vtData;
    if (pResult->Get(L"KeyProtectorKey", 0, &vtData, 0, 0) == S_OK) {
        if (vtData.vt == (VT_ARRAY | VT_UI1)) {
            SAFEARRAY* pArray = vtData.parray;
            BYTE* pData = nullptr;
            SafeArrayAccessData(pArray, (void**)&pData);
            LONG count = pArray->rgsabound[0].cElements;
            key.KeyData.resize(count);
            memcpy(key.KeyData.data(), pData, count);
            SafeArrayUnaccessData(pArray);
        }
        VariantClear(&vtData);
    }

    if (key.ProtectorType == L"NumericalPassword") {
        key.NumericalPassword.resize(key.KeyData.size() + 1, 0);
        memcpy(&key.NumericalPassword[0], key.KeyData.data(), key.KeyData.size());
        key.NumericalPassword.resize(wcslen(key.NumericalPassword.c_str()));
    }

    pResult->Release();
    return true;
}

bool BitLockerManager::SetNumericalPassword(const std::wstring& driveLetter, const std::wstring& password) {
    std::wstring objPath = L"Win32_EncryptableVolume.DriveLetter=\"" + driveLetter + L"\"";

    IWbemClassObject* pInClass = nullptr;
    HRESULT hr = m_pServices->GetObject(
        bstr_t((objPath + L"\\ProtectKeyWithNumericalPassword").c_str()), 0, NULL, &pInClass, NULL);
    if (FAILED(hr) || !pInClass) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastError = L"ProtectKeyWithNumericalPassword method not found";
        return false;
    }

    IWbemClassObject* pParams = nullptr;
    pInClass->SpawnInstance(0, &pParams);
    VARIANT vt;
    vt.vt = VT_BSTR;
    vt.bstrVal = SysAllocString(password.c_str());
    pParams->Put(L"NumericalPassword", 0, &vt, 0);
    VariantClear(&vt);
    pInClass->Release();

    IWbemClassObject* pResult = ExecMethod(objPath, L"ProtectKeyWithNumericalPassword", pParams);
    if (pParams) pParams->Release();
    if (!pResult) return false;

    pResult->Release();
    return true;
}

std::wstring BitLockerManager::GetLastError() noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_lastError;
}
