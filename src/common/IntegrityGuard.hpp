#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <atomic>

struct ProcessSnapshot {
    DWORD   Pid;
    std::wstring Name;
    BYTE    TextSectionHash[32];
    SIZE_T  TextSectionSize;
};

class IntegrityGuard {
public:
    [[nodiscard]] static bool SnapshotProcess(DWORD pid, ProcessSnapshot& snap);
    [[nodiscard]] static bool VerifyProcess(const ProcessSnapshot& snap) noexcept;
    [[nodiscard]] static bool GetProcessTextHash(DWORD pid, BYTE hash[32], SIZE_T& size);
};
