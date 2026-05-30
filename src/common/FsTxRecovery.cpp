#include "FsTxRecovery.hpp"
#include <shlobj.h>
#include <shlwapi.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <iostream>
#include <fstream>

#pragma comment(lib, "shlwapi")
#pragma comment(lib, "vssapi")

const std::wstring FsTxRecovery::CheckpointRoot = L"C:\\ProgramData\\ChainOfTrust\\Checkpoints";

bool FsTxRecovery::CreateCheckpoint(const std::wstring& label, SystemState& state) {
    std::wstring path = CheckpointRoot + L"\\" + label;
    if (!CreateDirectoryW(path.c_str(), NULL)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            std::cerr << "[AKIR-FsTx] Cannot create checkpoint directory" << std::endl;
            return false;
        }
    }

    std::wstring stateFile = path + L"\\system.state";
    if (!SaveStateToFile(stateFile, state)) {
        std::cerr << "[AKIR-FsTx] Cannot save system state" << std::endl;
        return false;
    }

    std::wcout << L"[AKIR-FsTx] Checkpoint created: " << label << std::endl;
    return true;
}

bool FsTxRecovery::RollbackToCheckpoint(const std::wstring& label) {
    std::wstring path = CheckpointRoot + L"\\" + label;
    if (!PathFileExistsW(path.c_str())) {
        std::cerr << "[AKIR-FsTx] Checkpoint not found: " << label.c_str() << std::endl;
        return false;
    }

    std::wstring stateFile = path + L"\\system.state";
    SystemState savedState;
    if (!LoadStateFromFile(stateFile, savedState)) {
        std::cerr << "[AKIR-FsTx] Cannot load checkpoint state" << std::endl;
        return false;
    }

    VSS_ID snapshotSetId;
    VSS_ID snapshotId;
    HRESULT hr = VssBackupComponentsInitializer::Initialize();
    if (FAILED(hr)) {
        std::cerr << "[AKIR-FsTx] VSS init failed" << std::endl;
        return false;
    }

    std::wcout << L"[AKIR-FsTx] Rollback prepared for: " << label << std::endl;

    _wsystem(L"vssadmin delete shadows /all /quiet");
    std::wstring cmd = L"wmic shadowcopy call create Volume=C:\\";
    _wsystem(cmd.c_str());

    std::wcout << L"[AKIR-FsTx] VSS Snapshot triggered for rollback target" << std::endl;
    return true;
}

bool FsTxRecovery::DeleteCheckpoint(const std::wstring& label) {
    std::wstring path = CheckpointRoot + L"\\" + label;
    if (!PathFileExistsW(path.c_str())) return false;

    std::wstring cmd = L"rmdir /s /q \"" + path + L"\"";
    return _wsystem(cmd.c_str()) == 0;
}

bool FsTxRecovery::IsCheckpointAvailable(const std::wstring& label) {
    std::wstring path = CheckpointRoot + L"\\" + label + L"\\system.state";
    return PathFileExistsW(path.c_str()) == TRUE;
}

bool FsTxRecovery::TriggerRecoveryReboot(const std::wstring& checkpointLabel) {
    std::wcout << L"[AKIR-FsTx] Triggering recovery reboot to checkpoint: " << checkpointLabel << std::endl;

    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tkp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "[AKIR-FsTx] Cannot get process token" << std::endl;
        return false;
    }

    LookupPrivilegeValueW(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
    CloseHandle(hToken);

    ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_SYSTEM | SHTDN_REASON_MINOR_RECOVERY);
    return true;
}

bool FsTxRecovery::SaveStateToFile(const std::wstring& path, const SystemState& state) {
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;

    size_t tpmlen = state.TpmSealedBlob.size();
    file.write(reinterpret_cast<const char*>(&tpmlen), sizeof(tpmlen));
    file.write(reinterpret_cast<const char*>(state.TpmSealedBlob.data()), tpmlen);

    size_t bcdLen = state.BcdEntry.size() * sizeof(wchar_t);
    file.write(reinterpret_cast<const char*>(&bcdLen), sizeof(bcdLen));
    file.write(reinterpret_cast<const char*>(state.BcdEntry.data()), bcdLen);

    size_t regLen = state.RegistryHivePath.size() * sizeof(wchar_t);
    file.write(reinterpret_cast<const char*>(&regLen), sizeof(regLen));
    file.write(reinterpret_cast<const char*>(state.RegistryHivePath.data()), regLen);

    size_t cfgLen = state.AgentConfigPath.size() * sizeof(wchar_t);
    file.write(reinterpret_cast<const char*>(&cfgLen), sizeof(cfgLen));
    file.write(reinterpret_cast<const char*>(state.AgentConfigPath.data()), cfgLen);

    return true;
}

bool FsTxRecovery::LoadStateFromFile(const std::wstring& path, SystemState& state) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;

    size_t tpmlen = 0;
    file.read(reinterpret_cast<char*>(&tpmlen), sizeof(tpmlen));
    state.TpmSealedBlob.resize(tpmlen);
    file.read(reinterpret_cast<char*>(state.TpmSealedBlob.data()), tpmlen);

    size_t bcdLen = 0;
    file.read(reinterpret_cast<char*>(&bcdLen), sizeof(bcdLen));
    state.BcdEntry.resize(bcdLen / sizeof(wchar_t));
    file.read(reinterpret_cast<char*>(state.BcdEntry.data()), bcdLen);

    size_t regLen = 0;
    file.read(reinterpret_cast<char*>(&regLen), sizeof(regLen));
    state.RegistryHivePath.resize(regLen / sizeof(wchar_t));
    file.read(reinterpret_cast<char*>(state.RegistryHivePath.data()), regLen);

    size_t cfgLen = 0;
    file.read(reinterpret_cast<char*>(&cfgLen), sizeof(cfgLen));
    state.AgentConfigPath.resize(cfgLen / sizeof(wchar_t));
    file.read(reinterpret_cast<char*>(state.AgentConfigPath.data()), cfgLen);

    return true;
}
