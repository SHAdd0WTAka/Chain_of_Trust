#include <windows.h>
#include <iostream>
#include <thread>
#include <atomic>
#include "../common/crypto.hpp"
#include "../common/ipc.hpp"

std::atomic<bool> g_running{true};

// Dummy placeholders for functions mentioned in README but not fully implemented there
void LoadKernelDriver(const std::wstring& path) { (void)path; }
PROCESS_INFORMATION StartProtectedProcess(const std::wstring& path) { (void)path; return {}; }
void MonitorLoop(DWORD pid) { (void)pid; }

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcout << L"Usage: EDRAgent.exe <protected.exe>\n";
        return 1;
    }
    const std::wstring path = argv[1];

    LoadKernelDriver(L"edrdrv.sys");
    PROCESS_INFORMATION pi = StartProtectedProcess(path);

    std::thread mon(MonitorLoop, pi.dwProcessId);
    WaitForSingleObject(pi.hProcess, INFINITE);
    g_running = false;
    mon.join();
    return 0;
}

