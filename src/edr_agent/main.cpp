#include <windows.h>
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

std::atomic<bool> g_running{true};
std::atomic<bool> g_integrityOk{true};

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

int wmain(int argc, wchar_t* argv[]) {
    std::cout << "=== AKIR: Advanced Kernel Integrity & Resilience ===" << std::endl;
    std::cout << "Chain_of_Trust - FsTx Dual-State Recovery Framework" << std::endl;
    std::cout << "====================================================" << std::endl;

    RecoverFromCrash();
    TpmStatusCheck();

    std::thread adminThread(AdminResetLoop);
    std::thread integrityThread(IntegrityMonitorLoop);
    std::thread timerThread(TimerCheckLoop);

    std::cout << "[AKIR] All subsystems active. Monitoring started." << std::endl;

    if (argc >= 2) {
        std::wcout << L"[AKIR] Protecting process: " << argv[1] << std::endl;
    }

    HANDLE hDevice = INVALID_HANDLE_VALUE;
    if (OpenAKIRDevice(hDevice)) {
        DWORD ourPid = GetCurrentProcessId();
        SendIoctlRegisterProtect(hDevice, ourPid);
        StartIntegrityMonitoring();
        CloseAKIRDevice(hDevice);
    }

    integrityThread.join();
    adminThread.join();
    timerThread.join();

    return 0;
}
