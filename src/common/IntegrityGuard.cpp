#include "IntegrityGuard.hpp"
#include "crypto.hpp"
#include <psapi.h>
#include <tlhelp32.h>
#include <vector>
#include <iostream>

#pragma comment(lib, "psapi")

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
    ReadProcessMemory(hProcess, modInfo.lpBaseOfDll, &dosHdr, sizeof(dosHdr), NULL);

    IMAGE_NT_HEADERS ntHdr = { 0 };
    ReadProcessMemory(hProcess, (BYTE*)modInfo.lpBaseOfDll + dosHdr.e_lfanew, &ntHdr, sizeof(ntHdr), NULL);

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

    if (!foundText) { CloseHandle(hProcess); return false; }

    size = textSection.SizeOfRawData;
    std::vector<BYTE> textData(textSection.SizeOfRawData);
    SIZE_T bytesRead = 0;
    BOOL ok = ReadProcessMemory(hProcess, (BYTE*)modInfo.lpBaseOfDll + textSection.VirtualAddress,
        textData.data(), textSection.SizeOfRawData, &bytesRead);
    CloseHandle(hProcess);

    if (!ok || bytesRead != textSection.SizeOfRawData) return false;
    return Crypto::Sha256(textData.data(), textData.size(), hash);
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
    if (!GetProcessTextHash(snap.Pid, currentHash, currentSize)) return false;
    return (currentSize == snap.TextSectionSize) && (memcmp(currentHash, snap.TextSectionHash, 32) == 0);
}
