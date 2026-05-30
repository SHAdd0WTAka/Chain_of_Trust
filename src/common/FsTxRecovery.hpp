#pragma once
#include <windows.h>
#include <string>
#include <vector>

struct SystemState {
    std::vector<BYTE> TpmSealedBlob;
    std::wstring      BcdEntry;
    std::wstring      RegistryHivePath;
    std::wstring      AgentConfigPath;
};

class FsTxRecovery {
public:
    static bool CreateCheckpoint(const std::wstring& label, SystemState& state);
    static bool RollbackToCheckpoint(const std::wstring& label);
    static bool DeleteCheckpoint(const std::wstring& label);
    static bool IsCheckpointAvailable(const std::wstring& label);
    static bool TriggerRecoveryReboot(const std::wstring& checkpointLabel);

private:
    static const std::wstring CheckpointRoot;
    static bool SaveStateToFile(const std::wstring& path, const SystemState& state);
    static bool LoadStateFromFile(const std::wstring& path, SystemState& state);
};
