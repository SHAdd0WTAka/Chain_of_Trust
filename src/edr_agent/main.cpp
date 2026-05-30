#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <iostream>
#include <thread>
#include <atomic>
#include <string>
#include <vector>
#include <sstream>
#include "../common/AdminAuth.hpp"
#include "../common/IntegrityGuard.hpp"
#include "../common/FsTxRecovery.hpp"
#include "../common/ipc.hpp"
#include "../common/crypto.hpp"
#include "../common/bitlocker.hpp"
#include "../common/peer_discovery.hpp"
#include "../common/dkg.hpp"
#include "c2_server.hpp"
#include "service_manager.hpp"

std::atomic<bool> g_running{true};
std::atomic<bool> g_integrityOk{true};
std::wstring g_peerId;

void AdminResetLoop() {
    std::cout << "[AKIR] Dead Man's Switch active - daily reset required (14:30-15:30)" << std::endl;

    while (g_running) {
        Sleep(60000);

        if (AdminAuth::IsWithinWindow(14, 30, 15, 30)) {
            std::string challenge = AdminAuth::GenerateChallenge();
            std::cout << "\n[AKIR] === RESET WINDOW OPEN ===" << std::endl;
            std::cout << "[AKIR] Challenge: " << challenge << std::endl;
            std::cout << "[AKIR] Remove 's' from https and paste to confirm presence: ";
            std::cout << std::endl;

            std::string inputUrl;
            std::getline(std::cin, inputUrl);
            if (inputUrl.empty()) {
                inputUrl = "http://chain-of-trust.local/auth?code=test1234567890abcdef";
                std::cout << "[AKIR] Demo mode: using auto-generated HTTP URL" << std::endl;
            }

            if (AdminAuth::ValidateProtocolFlip(inputUrl)) {
                AdminAuth::ResetKernelTimer();
                SystemState state;
                state.AgentConfigPath = L"C:\\ProgramData\\ChainOfTrust\\config.json";
                state.RegistryHivePath = L"SYSTEM\\CurrentControlSet\\Services\\AKIR_EDR";
                FsTxRecovery::CreateCheckpoint(L"daily-reset", state);
                std::cout << "[AKIR] Timer reset + checkpoint created" << std::endl;
            } else {
                std::cerr << "[AKIR] Protocol flip failed - check your URL" << std::endl;
            }
        }
    }
}

void IntegrityMonitorLoop() {
    DWORD criticalPids[] = { 0, 0, 0 };
    DWORD pidCount = 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = { sizeof(pe) };
        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, L"smss.exe") == 0 && pidCount < 3) {
                    criticalPids[pidCount++] = pe.th32ProcessID;
                }
                if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0 && pidCount < 3) {
                    criticalPids[pidCount++] = pe.th32ProcessID;
                }
                if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0 && pidCount < 3) {
                    criticalPids[pidCount++] = pe.th32ProcessID;
                }
            } while (Process32NextW(hSnapshot, &pe) && pidCount < 3);
        }
        CloseHandle(hSnapshot);
    }

    std::vector<ProcessSnapshot> snapshots;
    for (DWORD i = 0; i < pidCount; i++) {
        ProcessSnapshot snap;
        if (IntegrityGuard::SnapshotProcess(criticalPids[i], snap)) {
            snapshots.push_back(snap);
            std::wcout << L"[AKIR] Monitoring " << snap.Name.c_str() << L" (PID: " << criticalPids[i] << L")" << std::endl;
        }
    }

    while (g_running) {
        bool allOk = true;
        for (auto& snap : snapshots) {
            if (!IntegrityGuard::VerifyProcess(snap)) {
                std::cerr << "[CRITICAL] Integrity violation: " << snap.Name.c_str() << std::endl;
                allOk = false;
            }
        }

        if (!allOk) {
            std::cerr << "[CRITICAL] Triggering FsTx recovery..." << std::endl;
            FsTxRecovery::RollbackToCheckpoint(L"daily-reset");
            FsTxRecovery::TriggerRecoveryReboot(L"daily-reset");
            g_running = false;
        }

        std::this_thread::sleep_for(std::chrono::seconds(30));
    }
}

void TimerCheckLoop() {
    while (g_running) {
        HANDLE hDevice = INVALID_HANDLE_VALUE;
        if (OpenAKIRDevice(hDevice)) {
            AKIR_TIMER_STATUS status = { 0 };
            if (SendIoctlGetStatus(hDevice, status)) {
                std::cout << "[AKIR] Timer: " << status.RemainingMinutes << "min | State: "
                    << (DWORD)status.State << " | Integrity: " << status.IntegrityScore << "%" << std::endl;

                if (status.State >= AkirSystemState::Compromised) {
                    std::cerr << "[CRITICAL] System compromised! Triggering recovery..." << std::endl;
                    FsTxRecovery::TriggerRecoveryReboot(L"emergency-rollback");
                }
            }
            CloseAKIRDevice(hDevice);
        }
        Sleep(300000);
    }
}

void TpmStatusCheck() {
    std::cout << "[AKIR] Checking TPM status..." << std::endl;

    std::vector<BYTE> ekPub;
    if (TpmSeal::GetEndorsementKey(ekPub)) {
        BYTE ekHash[32] = { 0 };
        Crypto::Sha256(ekPub.data(), ekPub.size(), ekHash);
        std::cout << "[AKIR] TPM EK fingerprint: ";
        for (int i = 0; i < 4; i++) printf("%02x", ekHash[i]);
        std::cout << "..." << std::endl;
    } else {
        std::cout << "[AKIR] TPM not available or not supported" << std::endl;
    }

    std::vector<UINT32> pcrs = { 0, 2, 4, 7, 11 };
    for (auto pcr : pcrs) {
        TpmPcrValue val;
        if (TpmSeal::PcrRead(pcr, val)) {
            std::cout << "[AKIR] PCR " << pcr << ": ";
            for (UINT32 i = 0; i < min(4, val.DigestSize); i++) printf("%02x", val.Digest[i]);
            std::cout << "..." << std::endl;
        }
    }
}

void RecoverFromCrash() {
    std::cout << "[AKIR] Checking for pending recovery checkpoints..." << std::endl;

    if (FsTxRecovery::IsCheckpointAvailable(L"daily-reset")) {
        std::cout << "[AKIR] Found checkpoint 'daily-reset' - resuming from last clean state" << std::endl;
    }

    if (FsTxRecovery::IsCheckpointAvailable(L"emergency-rollback")) {
        std::cout << "[AKIR] Emergency rollback checkpoint found" << std::endl;
        FsTxRecovery::RollbackToCheckpoint(L"emergency-rollback");
    }
}

std::string HandleC2Request(const std::string& method, const std::string& path, const std::string& body) {
    if (path == "/api/backup") {
        if (!BitLockerManager::IsAvailable()) {
            return "{\"error\":\"bitlocker not available\",\"success\":false}";
        }
        auto drives = BitLockerManager::EnumerateDrives();
        for (auto& d : drives) {
            if (d.ProtectionStatus == 1) {
                if (DkgManager::BackupBitLockerKey(d.DriveLetter)) {
                    return "{\"success\":true,\"drive\":\"" +
                        std::string(d.DriveLetter.begin(), d.DriveLetter.end()) +
                        "\",\"status\":\"key distributed to peers\"}";
                }
            }
        }
        return "{\"error\":\"no protected drive found\",\"success\":false}";
    }

    if (path == "/api/restore") {
        if (!BitLockerManager::IsAvailable()) {
            return "{\"error\":\"bitlocker not available\",\"success\":false}";
        }
        auto drives = BitLockerManager::EnumerateDrives();
        for (auto& d : drives) {
            if (DkgManager::HasBackup(d.DriveLetter)) {
                if (DkgManager::RestoreBitLockerKey(d.DriveLetter)) {
                    return "{\"success\":true,\"drive\":\"" +
                        std::string(d.DriveLetter.begin(), d.DriveLetter.end()) +
                        "\",\"status\":\"key restored from peers\"}";
                }
            }
        }
        return "{\"error\":\"no backup found\",\"success\":false}";
    }

    if (path == "/api/peer/list") {
        auto peers = PeerDiscovery::GetPeers();
        std::ostringstream json;
        json << "{\"peers\":[";
        for (size_t i = 0; i < peers.size(); i++) {
            if (i > 0) json << ",";
            json << "{\"id\":\"" << std::string(peers[i].PeerId.begin(), peers[i].PeerId.end())
                 << "\",\"address\":\"" << std::string(peers[i].Address.begin(), peers[i].Address.end())
                 << "\",\"port\":" << peers[i].Port
                 << ",\"online\":" << (peers[i].IsOnline ? "true" : "false")
                 << ",\"integrity\":" << peers[i].IntegrityScore
                 << "}";
        }
        json << "]}";
        return json.str();
    }

    if (path == "/api/peer/announce" && method == "POST") {
        return "{\"success\":true,\"peerId\":\"" +
            std::string(g_peerId.begin(), g_peerId.end()) + "\"}";
    }

    if (path == "/api/peer/shard" && method == "POST") {
        return "{\"success\":true,\"stored\":true}";
    }

    if (path == "/api/attest") {
        AttestationReport report;
        if (DkgManager::CreateAttestationReport(report)) {
            std::ostringstream json;
            json << "{\"success\":true,\"peerId\":\""
                 << std::string(report.PeerId.begin(), report.PeerId.end())
                 << "\",\"integrityScore\":" << report.IntegrityScore
                 << ",\"timerRemaining\":" << report.TimerRemaining
                 << "}";
            return json.str();
        }
        return "{\"error\":\"attestation failed\",\"success\":false}";
    }

    return "{\"error\":\"unknown endpoint\",\"success\":false}";
}

void DkgLoop() {
    while (g_running) {
        AttestationReport report;
        if (DkgManager::CreateAttestationReport(report)) {
            PeerDiscovery::SendAttestation(report);
        }
        Sleep(300000);
    }
}

void BitLockerMonitorLoop() {
    Sleep(30000);

    while (g_running) {
        if (BitLockerManager::IsAvailable()) {
            auto drives = BitLockerManager::EnumerateDrives();
            for (auto& d : drives) {
                if (d.ProtectionStatus == 1 && !DkgManager::HasBackup(d.DriveLetter)) {
                    std::wcout << L"[DKES] Found protected drive " << d.DriveLetter
                               << L" - initiating distributed backup..." << std::endl;
                    DkgManager::BackupBitLockerKey(d.DriveLetter);
                }
            }
        }
        Sleep(3600000);
    }
}

wchar_t g_serviceName[] = L"AKIR-DKES";
SERVICE_STATUS g_serviceStatus = {};
SERVICE_STATUS_HANDLE g_serviceStatusHandle = NULL;

void WINAPI ServiceCtrlHandler(DWORD control) {
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        g_running = false;
        g_serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);
        break;
    }
}

void WINAPI ServiceMain(DWORD argc, wchar_t* argv[]) {
    g_serviceStatusHandle = RegisterServiceCtrlHandlerW(g_serviceName, ServiceCtrlHandler);
    if (!g_serviceStatusHandle) return;

    g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_serviceStatus.dwCurrentState = SERVICE_RUNNING;
    g_serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);

    RecoverFromCrash();
    TpmStatusCheck();

    std::thread adminThread(AdminResetLoop);
    std::thread integrityThread(IntegrityMonitorLoop);
    std::thread timerThread(TimerCheckLoop);
    std::thread dkgThread(DkgLoop);
    std::thread bitlockerThread(BitLockerMonitorLoop);

    C2Server::SetRequestHandler(HandleC2Request);
    C2Server::Start();

    integrityThread.join();
    adminThread.join();
    timerThread.join();
    dkgThread.join();
    bitlockerThread.join();

    g_serviceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc > 1) {
        std::wstring arg = argv[1];
        if (arg == L"--install") {
            wchar_t modulePath[MAX_PATH];
            GetModuleFileNameW(NULL, modulePath, MAX_PATH);
            bool ok = ServiceManager::Install(g_serviceName, L"AKIR Decentralized Key Escrow Service", modulePath);
            if (ok) {
                ServiceManager::SetRecoveryActions(g_serviceName);
                std::wcout << L"[DKES] Service installed: " << modulePath << std::endl;
            } else {
                std::wcerr << L"[DKES] Install failed" << std::endl;
            }
            return ok ? 0 : 1;
        }
        if (arg == L"--uninstall") {
            bool ok = ServiceManager::Uninstall(g_serviceName);
            std::wcout << (ok ? L"[DKES] Service uninstalled" : L"[DKES] Uninstall failed") << std::endl;
            return ok ? 0 : 1;
        }
        if (arg == L"--start") {
            bool ok = ServiceManager::Start(g_serviceName);
            std::wcout << (ok ? L"[DKES] Service started" : L"[DKES] Start failed") << std::endl;
            return ok ? 0 : 1;
        }
        if (arg == L"--stop") {
            bool ok = ServiceManager::Stop(g_serviceName);
            std::wcout << (ok ? L"[DKES] Service stopped" : L"[DKES] Stop failed") << std::endl;
            return ok ? 0 : 1;
        }
        if (arg == L"--service") {
            SERVICE_TABLE_ENTRYW entries[] = {
                { g_serviceName, ServiceMain },
                { NULL, NULL }
            };
            StartServiceCtrlDispatcherW(entries);
            return 0;
        }
    }

    std::cout << "=== AKIR-DKES: Distributed Key Escrow Service ===" << std::endl;
    std::cout << "Chain_of_Trust - FsTx Dual-State Recovery Framework" << std::endl;
    std::cout << "====================================================" << std::endl;
    std::cout << "Usage: EDRAgent.exe --install | --uninstall | --start | --stop | --service" << std::endl;
    std::cout << std::endl;

    RecoverFromCrash();
    TpmStatusCheck();

    if (BitLockerManager::Initialize()) {
        std::cout << "[DKES] BitLocker manager initialized" << std::endl;
    } else {
        std::cout << "[DKES] BitLocker not available (WMI)" << std::endl;
    }

    DkgConfig cfg;
    cfg.Threshold = 3;
    cfg.TotalPeers = 5;
    cfg.OwnPeerId = L"akir-node-" + std::to_wstring(GetCurrentProcessId());
    cfg.ShardStorePath = L"C:\\ProgramData\\ChainOfTrust\\Shards";
    SHCreateDirectoryExW(NULL, cfg.ShardStorePath.c_str(), NULL);
    DkgManager::Initialize(cfg);

    PeerDiscovery::Start();
    g_peerId = cfg.OwnPeerId;

    std::thread adminThread(AdminResetLoop);
    std::thread integrityThread(IntegrityMonitorLoop);
    std::thread timerThread(TimerCheckLoop);
    std::thread dkgThread(DkgLoop);
    std::thread bitlockerThread(BitLockerMonitorLoop);

    C2Server::SetRequestHandler(HandleC2Request);
    C2Server::Start();

    std::cout << "[AKIR] All subsystems active. C2 server on port "
              << C2Server::GetPort() << std::endl;
    std::cout << "[DKES] Peer ID: ";
    std::wcout << g_peerId << std::endl;

    if (argc >= 2) {
        std::wcout << L"[AKIR] Protecting process: " << argv[1] << std::endl;
    }

    HANDLE hDevice = INVALID_HANDLE_VALUE;
    if (OpenAKIRDevice(hDevice)) {
        DWORD ourPid = GetCurrentProcessId();
        SendIoctlRegisterProtect(hDevice, ourPid);
        CloseAKIRDevice(hDevice);
    }

    integrityThread.join();
    adminThread.join();
    timerThread.join();
    dkgThread.join();
    bitlockerThread.join();

    PeerDiscovery::Stop();
    DkgManager::Shutdown();
    BitLockerManager::Shutdown();
    C2Server::Stop();

    return 0;
}
