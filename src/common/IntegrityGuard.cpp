#include "IntegrityGuard.hpp"
#include "crypto.hpp"
#include <psapi.h>
#include <tlhelp32.h>
#include <vector>
#include <iostream>
#include <atomic>
#include <thread>

#pragma comment(lib, "psapi")

bool IntegrityGuard::ReadProcessMemoryRemote(DWORD pid, const BYTE* addr, SIZE_T size, std::vector<BYTE>& out) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return false;

    out.resize(size);
    SIZE_T bytesRead = 0;
    BOOL result = ReadProcessMemory(hProcess, addr, out.data(), size, &bytesRead);
    CloseHandle(hProcess);

    if (!result || bytesRead != size) return false;
    return true;
}

bool IntegrityGuard::GetProcessTextHash(DWORD pid, BYTE hash[32], SIZE_T& size) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;

    HMODULE hMod = NULL;
    DWORD cbNeeded = 0;
    if (!EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
        CloseHandle(hProcess);
        return false;
    }

    MODULEINFO modInfo = { 0 };
    if (!GetModuleInformation(hProcess, hMod, &modInfo, sizeof(modInfo))) {
        CloseHandle(hProcess);
        return false;
    }

    IMAGE_DOS_HEADER dosHdr = { 0 };
    if (!ReadProcessMemory(hProcess, modInfo.lpBaseOfDll, &dosHdr, sizeof(dosHdr), NULL)) {
        CloseHandle(hProcess);
        return false;
    }

    IMAGE_NT_HEADERS ntHdr = { 0 };
    if (!ReadProcessMemory(hProcess, (BYTE*)modInfo.lpBaseOfDll + dosHdr.e_lfanew, &ntHdr, sizeof(ntHdr), NULL)) {
        CloseHandle(hProcess);
        return false;
    }

    IMAGE_SECTION_HEADER textSection = { 0 };
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(&ntHdr);
    BOOL foundText = FALSE;
    for (WORD i = 0; i < ntHdr.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec = { 0 };
        if (ReadProcessMemory(hProcess, (BYTE*)sections + i * sizeof(IMAGE_SECTION_HEADER), &sec, sizeof(sec), NULL)) {
            if (memcmp(sec.Name, ".text", 5) == 0) {
                textSection = sec;
                foundText = TRUE;
                break;
            }
        }
    }

    if (!foundText) {
        CloseHandle(hProcess);
        return false;
    }

    size = textSection.SizeOfRawData;
    std::vector<BYTE> textData;
    if (!ReadProcessMemoryRemote(pid, (BYTE*)modInfo.lpBaseOfDll + textSection.VirtualAddress, textSection.SizeOfRawData, textData)) {
        CloseHandle(hProcess);
        return false;
    }

    bool result = Crypto::Sha256(textData.data(), textData.size(), hash);
    CloseHandle(hProcess);
    return result;
}

bool IntegrityGuard::SnapshotProcess(DWORD pid, ProcessSnapshot& snap) {
    snap.Pid = pid;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = { sizeof(pe) };
    BOOL found = FALSE;
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                snap.Name = pe.szExeFile;
                found = TRUE;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);

    if (!found) return false;

    return GetProcessTextHash(pid, snap.TextSectionHash, snap.TextSectionSize);
}

bool IntegrityGuard::VerifyProcess(const ProcessSnapshot& snap) {
    BYTE currentHash[32] = { 0 };
    SIZE_T currentSize = 0;

    if (!GetProcessTextHash(snap.Pid, currentHash, currentSize)) {
        std::cerr << "[AKIR] Cannot read current hash for PID " << snap.Pid << std::endl;
        return false;
    }

    if (currentSize != snap.TextSectionSize) return false;
    return memcmp(currentHash, snap.TextSectionHash, 32) == 0;
}

bool IntegrityGuard::MonitorThread(DWORD pid, std::atomic<bool>& running) {
    ProcessSnapshot snap;
    if (!SnapshotProcess(pid, snap)) {
        std::cerr << "[AKIR] Cannot snapshot PID " << pid << std::endl;
        return false;
    }

    std::wcout << L"[AKIR] Monitoring " << snap.Name.c_str() << L" (PID: " << pid << L")" << std::endl;

    while (running) {
        if (!VerifyProcess(snap)) {
            std::cerr << "[CRITICAL] Integrity violation detected for PID " << pid << std::endl;
            return false;
        }
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }

    return true;
}
