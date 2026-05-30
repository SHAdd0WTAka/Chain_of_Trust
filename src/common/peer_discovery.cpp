#include "peer_discovery.hpp"
#include "crypto.hpp"
#include <sstream>
#include <random>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")

HANDLE PeerDiscovery::m_listenThread = NULL;
HANDLE PeerDiscovery::m_broadcastThread = NULL;
bool PeerDiscovery::m_running = false;
USHORT PeerDiscovery::m_port = 8444;
CRITICAL_SECTION PeerDiscovery::m_peersLock;
std::vector<PeerInfo> PeerDiscovery::m_peers;
std::function<void(const PeerInfo&)> PeerDiscovery::m_callback;

std::string PeerDiscovery::GeneratePeerId() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> hex(0, 15);

    std::ostringstream oss;
    oss << "AKIR-";
    for (int i = 0; i < 8; i++) {
        oss << std::hex << hex(gen);
    }
    return oss.str();
}

std::string PeerDiscovery::BuildDiscoveryMessage() {
    std::ostringstream oss;
    oss << "AKIR_PEER_DISCOVERY|";
    oss << GeneratePeerId() << "|";
    oss << m_port;
    return oss.str();
}

bool PeerDiscovery::SendUdpPacket(const std::wstring& address, USHORT port, const std::string& data) {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) return false;

    sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);

    if (address == L"255.255.255.255") {
        BOOL broadcast = TRUE;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char*)&broadcast, sizeof(broadcast));
        dest.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    } else {
        std::string addr Narrow(address.begin(), address.end());
        inet_pton(AF_INET, addr.c_str(), &dest.sin_addr);
    }

    int sent = sendto(sock, data.c_str(), (int)data.size(), 0, (sockaddr*)&dest, sizeof(dest));
    closesocket(sock);
    return sent > 0;
}

bool PeerDiscovery::RecvUdpPacket(SOCKET sock, std::string& outData, sockaddr_in& from) {
    char buf[4096];
    int fromLen = sizeof(from);
    int received = recvfrom(sock, buf, sizeof(buf) - 1, 0, (sockaddr*)&from, &fromLen);
    if (received > 0) {
        buf[received] = 0;
        outData = buf;
        return true;
    }
    return false;
}

void PeerDiscovery::ProcessDiscoveryMessage(const std::string& msg, const sockaddr_in& from) {
    std::istringstream iss(msg);
    std::string token;
    std::vector<std::string> parts;
    while (std::getline(iss, token, '|')) {
        parts.push_back(token);
    }

    if (parts.size() < 3 || parts[0] != "AKIR_PEER_DISCOVERY") return;

    char addrStr[64];
    inet_ntop(AF_INET, &from.sin_addr, addrStr, sizeof(addrStr));

    std::wstring wideAddr(addrStr, addrStr + strlen(addrStr));
    USHORT peerPort = (USHORT)std::stoul(parts[2]);

    EnterCriticalSection(&m_peersLock);
    bool found = false;
    for (auto& peer : m_peers) {
        if (peer.PeerId == std::wstring(parts[1].begin(), parts[1].end())) {
            peer.Address = wideAddr;
            peer.Port = peerPort;
            GetSystemTimeAsFileTime(&peer.LastSeen);
            peer.IsOnline = true;
            found = true;
            break;
        }
    }

    if (!found) {
        PeerInfo pi;
        pi.PeerId = std::wstring(parts[1].begin(), parts[1].end());
        pi.Address = wideAddr;
        pi.Port = peerPort;
        pi.IntegrityScore = 0;
        pi.IsOnline = true;
        GetSystemTimeAsFileTime(&pi.LastSeen);
        m_peers.push_back(pi);

        if (m_callback) {
            m_callback(pi);
        }
    }
    LeaveCriticalSection(&m_peersLock);
}

DWORD WINAPI PeerDiscovery::ListenThread(LPVOID param) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) return 1;

    sockaddr_in local;
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(m_port);

    bind(sock, (sockaddr*)&local, sizeof(local));

    fd_set readSet;
    TIMEVAL timeout = { 1, 0 };

    while (m_running) {
        FD_ZERO(&readSet);
        FD_SET(sock, &readSet);
        int result = select(0, &readSet, NULL, NULL, &timeout);
        if (result > 0 && FD_ISSET(sock, &readSet)) {
            sockaddr_in from;
            std::string data;
            if (RecvUdpPacket(sock, data, from)) {
                ProcessDiscoveryMessage(data, from);
            }
        }
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}

DWORD WINAPI PeerDiscovery::BroadcastThread(LPVOID param) {
    while (m_running) {
        std::string msg = BuildDiscoveryMessage();
        SendUdpPacket(L"255.255.255.255", m_port, msg);
        Sleep(60000);
    }
    return 0;
}

bool PeerDiscovery::Start(USHORT listenPort) {
    if (m_running) return true;

    m_port = listenPort;
    m_running = true;
    InitializeCriticalSection(&m_peersLock);

    m_broadcastThread = CreateThread(NULL, 0, BroadcastThread, NULL, 0, NULL);
    m_listenThread = CreateThread(NULL, 0, ListenThread, NULL, 0, NULL);

    return m_broadcastThread != NULL && m_listenThread != NULL;
}

void PeerDiscovery::Stop() {
    m_running = false;
    if (m_broadcastThread) {
        WaitForSingleObject(m_broadcastThread, 3000);
        CloseHandle(m_broadcastThread);
        m_broadcastThread = NULL;
    }
    if (m_listenThread) {
        WaitForSingleObject(m_listenThread, 3000);
        CloseHandle(m_listenThread);
        m_listenThread = NULL;
    }
    DeleteCriticalSection(&m_peersLock);
}

bool PeerDiscovery::IsRunning() {
    return m_running;
}

std::vector<PeerInfo> PeerDiscovery::GetPeers() {
    EnterCriticalSection(&m_peersLock);
    std::vector<PeerInfo> result = m_peers;
    LeaveCriticalSection(&m_peersLock);
    return result;
}

bool PeerDiscovery::AddStaticPeer(const std::wstring& address, USHORT port) {
    EnterCriticalSection(&m_peersLock);
    for (auto& peer : m_peers) {
        if (peer.Address == address && peer.Port == port) {
            LeaveCriticalSection(&m_peersLock);
            return true;
        }
    }

    PeerInfo pi;
    pi.PeerId = L"static-" + address;
    pi.Address = address;
    pi.Port = port;
    pi.IntegrityScore = 100;
    pi.IsOnline = false;
    GetSystemTimeAsFileTime(&pi.LastSeen);
    m_peers.push_back(pi);
    LeaveCriticalSection(&m_peersLock);
    return true;
}

bool PeerDiscovery::RemovePeer(const std::wstring& peerId) {
    EnterCriticalSection(&m_peersLock);
    auto it = std::remove_if(m_peers.begin(), m_peers.end(),
        [&](const PeerInfo& p) { return p.PeerId == peerId; });
    bool removed = it != m_peers.end();
    m_peers.erase(it, m_peers.end());
    LeaveCriticalSection(&m_peersLock);
    return removed;
}

bool PeerDiscovery::SendAttestation(AttestationReport& report) {
    EnterCriticalSection(&m_peersLock);
    for (auto& peer : m_peers) {
        if (!peer.IsOnline) continue;
        std::ostringstream oss;
        oss << "AKIR_ATTESTATION|";
        oss << std::string(report.PeerId.begin(), report.PeerId.end()) << "|";
        oss << report.IntegrityScore << "|";
        oss << report.TimerRemaining;

        std::string msg = oss.str();
        SendUdpPacket(peer.Address, peer.Port, msg);
    }
    LeaveCriticalSection(&m_peersLock);
    return true;
}

bool PeerDiscovery::RequestAttestation(const std::wstring& peerId, AttestationReport& outReport) {
    EnterCriticalSection(&m_peersLock);
    for (auto& peer : m_peers) {
        if (peer.PeerId == peerId && peer.IsOnline) {
            std::string msg = "AKIR_ATTESTATION_REQUEST|";
            SendUdpPacket(peer.Address, peer.Port, msg);
            LeaveCriticalSection(&m_peersLock);
            return true;
        }
    }
    LeaveCriticalSection(&m_peersLock);
    return false;
}

void PeerDiscovery::SetPeerCallback(std::function<void(const PeerInfo&)> callback) {
    m_callback = callback;
}
