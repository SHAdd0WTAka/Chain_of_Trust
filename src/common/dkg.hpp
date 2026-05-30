#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <functional>

struct DkgConfig {
    BYTE Threshold;     // M - minimum shards needed
    BYTE TotalPeers;    // N - total shards
    std::wstring OwnPeerId;
    std::wstring ShardStorePath;
};

struct DkgSession {
    std::wstring SessionId;
    std::wstring DriveLetter;
    std::vector<BYTE> LocalShard;     // TPM-sealed on this machine
    int LocalShardIndex;
    std::vector<int> RemoteShardIndices;
    bool IsComplete;
    FILETIME CreatedAt;
};

class DkgManager {
public:
    static bool Initialize(const DkgConfig& config);
    static void Shutdown();

    static bool BackupBitLockerKey(const std::wstring& driveLetter);
    static bool RestoreBitLockerKey(const std::wstring& driveLetter);

    static bool StoreShard(const std::wstring& fromPeerId, int shardIndex,
                           const std::vector<BYTE>& encryptedShard);
    static bool RetrieveShard(const std::wstring& fromPeerId, int shardIndex,
                              std::vector<BYTE>& outShard);

    static bool CreateAttestationReport(AttestationReport& outReport);
    static bool VerifyAttestationReport(const AttestationReport& report);

    static DkgSession GetCurrentSession();
    static bool HasBackup(const std::wstring& driveLetter);

    using ShardCallback = std::function<bool(const std::wstring&, int, const std::vector<BYTE>&)>;
    static void SetShardCallback(ShardCallback callback);

private:
    static DkgConfig m_config;
    static DkgSession m_currentSession;
    static ShardCallback m_shardCallback;
    static CRITICAL_SECTION m_lock;

    static std::wstring GetLocalShardPath(const std::wstring& sessionId);
    static std::wstring GenerateSessionId();
    static bool DistributeToPeers(const std::vector<Shard>& shards, int localIndex);
};
