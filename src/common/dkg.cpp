#include "dkg.hpp"
#include "shamir.hpp"
#include "bitlocker.hpp"
#include "crypto.hpp"
#include "peer_discovery.hpp"
#include "FsTxRecovery.hpp"
#include "IntegrityGuard.hpp"
#include <random>
#include <sstream>
#include <fstream>
#include <iomanip>

DkgConfig DkgManager::m_config = {};
DkgSession DkgManager::m_currentSession = {};
DkgManager::ShardCallback DkgManager::m_shardCallback = nullptr;
CRITICAL_SECTION DkgManager::m_lock;

bool DkgManager::Initialize(const DkgConfig& config) {
    InitializeCriticalSection(&m_lock);
    m_config = config;
    m_currentSession = {};
    return true;
}

void DkgManager::Shutdown() {
    DeleteCriticalSection(&m_lock);
}

std::wstring DkgManager::GenerateSessionId() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> hex(0, 15);

    std::wostringstream oss;
    oss << L"DKES-";
    for (int i = 0; i < 16; i++) {
        oss << std::hex << hex(gen);
    }
    return oss.str();
}

std::wstring DkgManager::GetLocalShardPath(const std::wstring& sessionId) {
    return m_config.ShardStorePath + L"\\" + sessionId + L".shard";
}

bool DkgManager::DistributeToPeers(const std::vector<Shard>& shards, int localIndex) {
    auto peers = PeerDiscovery::GetPeers();
    int peerIdx = 0;

    for (size_t i = 0; i < shards.size(); i++) {
        if ((int)i == localIndex) continue;

        if (peerIdx >= (int)peers.size() || !peers[peerIdx].IsOnline) {
            continue;
        }

        if (m_shardCallback) {
            m_shardCallback(peers[peerIdx].PeerId, (int)i, shards[i].Data);
        }
        peerIdx++;
    }
    return true;
}

bool DkgManager::BackupBitLockerKey(const std::wstring& driveLetter) {
    EnterCriticalSection(&m_lock);

    if (!BitLockerManager::IsAvailable()) {
        LeaveCriticalSection(&m_lock);
        return false;
    }

    auto drives = BitLockerManager::EnumerateDrives();
    BitLockerDrive* target = nullptr;
    for (auto& d : drives) {
        if (d.DriveLetter == driveLetter && d.ProtectionStatus == 1) {
            target = &d;
            break;
        }
    }
    if (!target) {
        LeaveCriticalSection(&m_lock);
        return false;
    }

    BitLockerKey recoveryKey;
    bool foundKey = false;
    auto protectors = BitLockerManager::GetKeyProtectors(driveLetter);
    for (auto& k : protectors) {
        if (k.ProtectorType == L"NumericalPassword" && !k.NumericalPassword.empty()) {
            recoveryKey = k;
            foundKey = true;
            break;
        }
    }

    if (!foundKey) {
        LeaveCriticalSection(&m_lock);
        return false;
    }

    std::wstring sessionId = GenerateSessionId();
    BYTE threshold = m_config.Threshold;
    BYTE total = m_config.TotalPeers;

    std::vector<BYTE> secret(
        (BYTE*)recoveryKey.NumericalPassword.c_str(),
        (BYTE*)recoveryKey.NumericalPassword.c_str() +
        (recoveryKey.NumericalPassword.size() * sizeof(wchar_t)));

    std::vector<Shard> shards;
    if (!Shamir::Split(secret, threshold, total, shards)) {
        LeaveCriticalSection(&m_lock);
        return false;
    }

    int localShardIndex = 0;

    std::vector<BYTE> localShardData = shards[localShardIndex].Data;
    std::vector<BYTE> sealedShard;
    std::vector<UINT32> pcrs = { 7, 11 };

    if (TpmSeal::Seal(localShardData, pcrs, sealedShard)) {
        localShardData = sealedShard;
    }

    std::wstring shardPath = GetLocalShardPath(sessionId);
    std::ofstream ofs(shardPath, std::ios::binary);
    if (ofs) {
        ofs.write((char*)localShardData.data(), localShardData.size());
        ofs.close();
    }

    DistributeToPeers(shards, localShardIndex);

    m_currentSession.SessionId = sessionId;
    m_currentSession.DriveLetter = driveLetter;
    m_currentSession.LocalShard = localShardData;
    m_currentSession.LocalShardIndex = localShardIndex;
    m_currentSession.IsComplete = false;
    GetSystemTimeAsFileTime(&m_currentSession.CreatedAt);

    LeaveCriticalSection(&m_lock);
    return true;
}

bool DkgManager::RestoreBitLockerKey(const std::wstring& driveLetter) {
    EnterCriticalSection(&m_lock);

    if (m_currentSession.SessionId.empty()) {
        LeaveCriticalSection(&m_lock);
        return false;
    }

    std::wstring shardPath = GetLocalShardPath(m_currentSession.SessionId);
    std::ifstream ifs(shardPath, std::ios::binary | std::ios::ate);
    if (!ifs) {
        LeaveCriticalSection(&m_lock);
        return false;
    }

    std::streamsize size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    std::vector<BYTE> localShardData((size_t)size);
    ifs.read((char*)localShardData.data(), size);
    ifs.close();

    std::vector<BYTE> unsealedData;
    if (TpmSeal::Unseal(localShardData, unsealedData)) {
        localShardData = unsealedData;
    }

    BYTE threshold = m_config.Threshold;
    std::vector<Shard> shards;
    Shard localShard;
    localShard.ParticipantId = (BYTE)(m_currentSession.LocalShardIndex + 1);
    localShard.Data = localShardData;
    shards.push_back(localShard);

    auto peers = PeerDiscovery::GetPeers();
    for (auto& peer : peers) {
        if (!peer.IsOnline) continue;
        if ((int)shards.size() >= threshold) break;

        std::vector<BYTE> peerShard;
        if (RetrieveShard(peer.PeerId, (int)shards.size(), peerShard) && !peerShard.empty()) {
            Shard s;
            s.ParticipantId = (BYTE)(shards.size() + 1);
            s.Data = peerShard;
            shards.push_back(s);
        }
    }

    if ((BYTE)shards.size() < threshold) {
        LeaveCriticalSection(&m_lock);
        return false;
    }

    std::vector<BYTE> recoveredSecret;
    if (!Shamir::Recover(shards, threshold, recoveredSecret)) {
        LeaveCriticalSection(&m_lock);
        return false;
    }

    std::wstring password((wchar_t*)recoveredSecret.data(),
                          recoveredSecret.size() / sizeof(wchar_t));

    if (!BitLockerManager::SetNumericalPassword(driveLetter, password)) {
        LeaveCriticalSection(&m_lock);
        return false;
    }

    m_currentSession.IsComplete = true;
    LeaveCriticalSection(&m_lock);
    return true;
}

bool DkgManager::StoreShard(const std::wstring& fromPeerId, int shardIndex,
                             const std::vector<BYTE>& encryptedShard) {
    std::wstring peerShardPath = m_config.ShardStorePath + L"\\peer_" +
        fromPeerId + L"_shard_" + std::to_wstring(shardIndex) + L".bin";

    std::ofstream ofs(peerShardPath, std::ios::binary);
    if (!ofs) return false;
    ofs.write((char*)encryptedShard.data(), encryptedShard.size());
    ofs.close();
    return true;
}

bool DkgManager::RetrieveShard(const std::wstring& fromPeerId, int shardIndex,
                                std::vector<BYTE>& outShard) {
    std::wstring peerShardPath = m_config.ShardStorePath + L"\\peer_" +
        fromPeerId + L"_shard_" + std::to_wstring(shardIndex) + L".bin";

    std::ifstream ifs(peerShardPath, std::ios::binary | std::ios::ate);
    if (!ifs) return false;

    std::streamsize size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    outShard.resize((size_t)size);
    ifs.read((char*)outShard.data(), size);
    ifs.close();
    return true;
}

bool DkgManager::CreateAttestationReport(AttestationReport& outReport) {
    outReport.PeerId = m_config.OwnPeerId;

    std::vector<UINT32> pcrs = { 0, 7, 11 };
    outReport.PcrDigest.clear();
    for (auto pcrIdx : pcrs) {
        TpmPcrValue pcr;
        if (TpmSeal::PcrRead(pcrIdx, pcr)) {
            outReport.PcrDigest.insert(outReport.PcrDigest.end(),
                pcr.Digest, pcr.Digest + pcr.DigestSize);
        }
    }

    outReport.IntegrityScore = 100;
    outReport.TimerRemaining = 1440;

    GetSystemTimeAsFileTime(&outReport.Timestamp);

    std::string toSign = std::to_string(outReport.IntegrityScore) +
                         std::to_string(outReport.TimerRemaining);
    BYTE hash[32];
    Crypto::Sha256((BYTE*)toSign.data(), toSign.size(), hash);
    outReport.Signature.assign(hash, hash + 32);

    return true;
}

bool DkgManager::VerifyAttestationReport(const AttestationReport& report) {
    if (report.IntegrityScore < 80) return false;
    if (report.TimerRemaining == 0) return false;

    std::string toVerify = std::to_string(report.IntegrityScore) +
                           std::to_string(report.TimerRemaining);
    BYTE hash[32];
    Crypto::Sha256((BYTE*)toVerify.data(), toVerify.size(), hash);

    if (report.Signature.size() != 32) return false;
    return memcmp(report.Signature.data(), hash, 32) == 0;
}

DkgSession DkgManager::GetCurrentSession() {
    EnterCriticalSection(&m_lock);
    DkgSession session = m_currentSession;
    LeaveCriticalSection(&m_lock);
    return session;
}

bool DkgManager::HasBackup(const std::wstring& driveLetter) {
    return !m_currentSession.SessionId.empty() &&
           m_currentSession.DriveLetter == driveLetter;
}

void DkgManager::SetShardCallback(ShardCallback callback) {
    m_shardCallback = callback;
}
