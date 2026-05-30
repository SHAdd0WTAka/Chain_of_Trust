#pragma once
#include <windows.h>
#include <string>
#include <vector>

struct ProcessSnapshot {
    DWORD   Pid;
    std::wstring Name;
    BYTE    TextSectionHash[32];
    SIZE_T  TextSectionSize;
};

class IntegrityGuard {
public:
    static bool SnapshotProcess(DWORD pid, ProcessSnapshot& snap);
    static bool VerifyProcess(const ProcessSnapshot& snap);
    static bool MonitorThread(DWORD pid, std::atomic<bool>& running);
    static bool GetProcessTextHash(DWORD pid, BYTE hash[32], SIZE_T& size);

private:
    static bool ReadProcessMemoryRemote(DWORD pid, const BYTE* addr, SIZE_T size, std::vector<BYTE>& out);
};
