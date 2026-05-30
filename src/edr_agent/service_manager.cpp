#include "service_manager.hpp"

SC_HANDLE ServiceManager::OpenScm(DWORD access) {
    return OpenSCManager(NULL, NULL, access);
}

std::wstring ServiceManager::GetLastErrorMsg() {
    wchar_t* msg = NULL;
    DWORD len = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, GetLastError(), 0, (LPWSTR)&msg, 0, NULL);
    std::wstring result(msg, len);
    LocalFree(msg);
    return result;
}

bool ServiceManager::Install(const std::wstring& serviceName, const std::wstring& displayName,
                              const std::wstring& binaryPath) {
    SC_HANDLE hScm = OpenScm(SC_MANAGER_CREATE_SERVICE);
    if (!hScm) return false;

    SC_HANDLE hSvc = CreateServiceW(hScm, serviceName.c_str(), displayName.c_str(),
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL, binaryPath.c_str(), NULL, NULL, NULL, NULL, NULL);

    if (hSvc) {
        SERVICE_DESCRIPTIONW desc;
        desc.lpDescription = (LPWSTR)L"AKIR-DKES: Decentralized Key Escrow Service - Integrity monitoring, TPM attestation, and distributed BitLocker key protection";
        ChangeServiceConfig2W(hSvc, SERVICE_CONFIG_DESCRIPTION, &desc);
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hScm);
        return true;
    }

    DWORD err = GetLastError();
    CloseServiceHandle(hScm);

    if (err == ERROR_SERVICE_EXISTS) return true;
    return false;
}

bool ServiceManager::Uninstall(const std::wstring& serviceName) {
    SC_HANDLE hScm = OpenScm(SC_MANAGER_ALL_ACCESS);
    if (!hScm) return false;

    SC_HANDLE hSvc = OpenServiceW(hScm, serviceName.c_str(), SERVICE_ALL_ACCESS);
    if (!hSvc) {
        CloseServiceHandle(hScm);
        return false;
    }

    SERVICE_STATUS status;
    ControlService(hSvc, SERVICE_CONTROL_STOP, &status);
    Sleep(2000);

    bool result = DeleteService(hSvc) != 0;

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return result;
}

bool ServiceManager::Start(const std::wstring& serviceName) {
    SC_HANDLE hScm = OpenScm(SC_MANAGER_CONNECT);
    if (!hScm) return false;

    SC_HANDLE hSvc = OpenServiceW(hScm, serviceName.c_str(), SERVICE_START);
    if (!hSvc) {
        CloseServiceHandle(hScm);
        return false;
    }

    bool result = StartServiceW(hSvc, 0, NULL) != 0;

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return result;
}

bool ServiceManager::Stop(const std::wstring& serviceName) {
    SC_HANDLE hScm = OpenScm(SC_MANAGER_CONNECT);
    if (!hScm) return false;

    SC_HANDLE hSvc = OpenServiceW(hScm, serviceName.c_str(), SERVICE_STOP);
    if (!hSvc) {
        CloseServiceHandle(hScm);
        return false;
    }

    SERVICE_STATUS status;
    bool result = ControlService(hSvc, SERVICE_CONTROL_STOP, &status) != 0;

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return result;
}

bool ServiceManager::Restart(const std::wstring& serviceName) {
    Stop(serviceName);
    Sleep(3000);
    return Start(serviceName);
}

ServiceStatus ServiceManager::Query(const std::wstring& serviceName) {
    ServiceStatus status = {};
    status.IsInstalled = false;
    status.IsRunning = false;

    SC_HANDLE hScm = OpenScm(SC_MANAGER_CONNECT);
    if (!hScm) return status;

    SC_HANDLE hSvc = OpenServiceW(hScm, serviceName.c_str(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!hSvc) {
        CloseServiceHandle(hScm);
        return status;
    }

    status.IsInstalled = true;

    SERVICE_STATUS_PROCESS ss;
    DWORD bytesNeeded = 0;
    if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (BYTE*)&ss,
                              sizeof(ss), &bytesNeeded)) {
        status.State = ss.dwCurrentState;
        status.IsRunning = (ss.dwCurrentState == SERVICE_RUNNING);
    }

    DWORD bufSize = 0;
    QueryServiceConfigW(hSvc, NULL, 0, &bufSize);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        LPQUERY_SERVICE_CONFIGW pConfig = (LPQUERY_SERVICE_CONFIGW)new BYTE[bufSize];
        if (QueryServiceConfigW(hSvc, pConfig, bufSize, &bufSize)) {
            status.DisplayName = pConfig->lpDisplayName;
            status.BinaryPath = pConfig->lpBinaryPathName;
        }
        delete[] pConfig;
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return status;
}

bool ServiceManager::SetRecoveryActions(const std::wstring& serviceName) {
    SC_HANDLE hScm = OpenScm(SC_MANAGER_ALL_ACCESS);
    if (!hScm) return false;

    SC_HANDLE hSvc = OpenServiceW(hScm, serviceName.c_str(), SERVICE_ALL_ACCESS);
    if (!hSvc) {
        CloseServiceHandle(hScm);
        return false;
    }

    SERVICE_FAILURE_ACTIONSW actions = {};
    SC_ACTION scActions[3];
    scActions[0].Type = SC_ACTION_RESTART;
    scActions[0].Delay = 30000;
    scActions[1].Type = SC_ACTION_RESTART;
    scActions[1].Delay = 60000;
    scActions[2].Type = SC_ACTION_RESTART;
    scActions[2].Delay = 120000;

    actions.dwResetPeriod = 86400;
    actions.lpRebootMsg = NULL;
    actions.lpCommand = NULL;
    actions.cActions = 3;
    actions.lpsaActions = scActions;

    bool result = ChangeServiceConfig2W(hSvc, SERVICE_CONFIG_FAILURE_ACTIONS, &actions) != 0;

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return result;
}
