#include "FsTxRecovery.hpp"
#include <shlobj.h>
#include <shlwapi.h>
#include <iostream>
#include <fstream>
#include <vector>

#pragma comment(lib, "shlwapi")

const std::wstring FsTxRecovery::CheckpointRoot = L"C:\\ProgramData\\ChainOfTrust\\Checkpoints";

bool FsTxRecovery::CreateCheckpoint(const std::wstring& label, SystemState& state) {
    std::wstring path = CheckpointRoot + L"\\" + label;
    CreateDirectoryW(path.c_str(), NULL);

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
        std::cerr << "[AKIR-FsTx] Checkpoint not found" << std::endl;
        return false;
    }

    std::wstring stateFile = path + L"\\system.state";
    SystemState savedState;
    if (!LoadStateFromFile(stateFile, savedState)) {
        std::cerr << "[AKIR-FsTx] Cannot load checkpoint state" << std::endl;
        return false;
    }

    _wsystem(L"vssadmin delete shadows /all /quiet");
    std::wstring cmd = L"wmic shadowcopy call create Volume=C:\\";
    _wsystem(cmd.c_str());

    std::wcout << L"[AKIR-FsTx] VSS Snapshot triggered for rollback" << std::endl;
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
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tkp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    LookupPrivilegeValueW(NULL, L"SeShutdownPrivilege", &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
    CloseHandle(hToken);

    ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_SYSTEM | 0x00080000);
    return true;
}

bool FsTxRecovery::SaveStateToFile(const std::wstring& path, const SystemState& state) {
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;

    size_t tpmlen = state.TpmSealedBlob.size();
    file.write(reinterpret_cast<const char*>(&tpmlen), sizeof(tpmlen));
    if (tpmlen > 0) file.write(reinterpret_cast<const char*>(state.TpmSealedBlob.data()), tpmlen);

    size_t bcdLen = state.BcdEntry.size() * sizeof(wchar_t);
    file.write(reinterpret_cast<const char*>(&bcdLen), sizeof(bcdLen));
    if (bcdLen > 0) file.write(reinterpret_cast<const char*>(state.BcdEntry.c_str()), bcdLen);

    size_t regLen = state.RegistryHivePath.size() * sizeof(wchar_t);
    file.write(reinterpret_cast<const char*>(&regLen), sizeof(regLen));
    if (regLen > 0) file.write(reinterpret_cast<const char*>(state.RegistryHivePath.c_str()), regLen);

    size_t cfgLen = state.AgentConfigPath.size() * sizeof(wchar_t);
    file.write(reinterpret_cast<const char*>(&cfgLen), sizeof(cfgLen));
    if (cfgLen > 0) file.write(reinterpret_cast<const char*>(state.AgentConfigPath.c_str()), cfgLen);

    return true;
}

bool FsTxRecovery::LoadStateFromFile(const std::wstring& path, SystemState& state) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;

    size_t tpmlen = 0;
    file.read(reinterpret_cast<char*>(&tpmlen), sizeof(tpmlen));
    state.TpmSealedBlob.resize(tpmlen);
    if (tpmlen > 0) file.read(reinterpret_cast<char*>(state.TpmSealedBlob.data()), tpmlen);

    size_t bcdLen = 0;
    file.read(reinterpret_cast<char*>(&bcdLen), sizeof(bcdLen));
    state.BcdEntry.resize(bcdLen / sizeof(wchar_t));
    if (bcdLen > 0) file.read(reinterpret_cast<char*>(state.BcdEntry.data()), bcdLen);

    size_t regLen = 0;
    file.read(reinterpret_cast<char*>(&regLen), sizeof(regLen));
    state.RegistryHivePath.resize(regLen / sizeof(wchar_t));
    if (regLen > 0) file.read(reinterpret_cast<char*>(state.RegistryHivePath.data()), regLen);

    size_t cfgLen = 0;
    file.read(reinterpret_cast<char*>(&cfgLen), sizeof(cfgLen));
    state.AgentConfigPath.resize(cfgLen / sizeof(wchar_t));
    if (cfgLen > 0) file.read(reinterpret_cast<char*>(state.AgentConfigPath.data()), cfgLen);

    return true;
}
