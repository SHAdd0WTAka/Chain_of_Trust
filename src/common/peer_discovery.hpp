#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <functional>

struct PeerInfo {
    std::wstring PeerId;
    std::wstring Address;
    USHORT Port;
    std::vector<BYTE> PublicKeyHash;
    FILETIME LastSeen;
    DWORD IntegrityScore;
    bool IsOnline;
};

struct AttestationReport {
    std::wstring PeerId;
    std::vector<BYTE> PcrDigest;
    DWORD IntegrityScore;
    DWORD TimerRemaining;
    FILETIME Timestamp;
    std::vector<BYTE> Signature;
};

class PeerDiscovery {
public:
    static bool Start(USHORT listenPort = 8444);
    static void Stop();
    static bool IsRunning();

    static std::vector<PeerInfo> GetPeers();
    static bool AddStaticPeer(const std::wstring& address, USHORT port);
    static bool RemovePeer(const std::wstring& peerId);

    static bool SendAttestation(AttestationReport& report);
    static bool RequestAttestation(const std::wstring& peerId, AttestationReport& outReport);

    static void SetPeerCallback(std::function<void(const PeerInfo&)> callback);

private:
    static HANDLE m_listenThread;
    static HANDLE m_broadcastThread;
    static bool m_running;
    static USHORT m_port;
    static CRITICAL_SECTION m_peersLock;
    static std::vector<PeerInfo> m_peers;
    static std::function<void(const PeerInfo&)> m_callback;

    static DWORD WINAPI ListenThread(LPVOID param);
    static DWORD WINAPI BroadcastThread(LPVOID param);
    static bool SendUdpPacket(const std::wstring& address, USHORT port, const std::string& data);
    static bool RecvUdpPacket(SOCKET sock, std::string& outData, sockaddr_in& from);
    static void ProcessDiscoveryMessage(const std::string& msg, const sockaddr_in& from);
    static std::string BuildDiscoveryMessage();
    static std::string GeneratePeerId();
};
