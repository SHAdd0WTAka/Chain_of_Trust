#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#include <string>

#define AKIR_DEVICE_NAME L"\\Device\\AKIR_EDR"
#define AKIR_DOS_DEVICE  L"\\\\.\\AKIR_EDR"

#define IOCTL_AKIR_RESET_TIMER      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_AKIR_GET_TIMER_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_AKIR_REGISTER_PROTECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_AKIR_UNREGISTER_PROTECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_AKIR_TPM_SEAL         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_AKIR_TPM_UNSEAL       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_AKIR_TRIGGER_RECOVERY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_AKIR_GET_STATE        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_READ_ACCESS)

enum class AkirSystemState : DWORD {
    Clean       = 0,
    Monitoring  = 1,
    TimerLow    = 2,
    Compromised = 3,
    Recovering  = 4,
    Honeypot    = 5
};

struct AKIR_TIMER_STATUS {
    DWORD       RemainingMinutes;
    AkirSystemState State;
    DWORD       IntegrityScore;
};

struct AKIR_PROTECT_REQUEST {
    DWORD  ProcessId;
    WCHAR  ProcessPath[260];
};

struct AKIR_TPM_REQUEST {
    BYTE   Data[512];
    DWORD  DataSize;
    BYTE   Output[1024];
    DWORD  OutputSize;
};

bool OpenAKIRDevice(HANDLE& hDevice);
void CloseAKIRDevice(HANDLE hDevice);
bool SendIoctlResetTimer(HANDLE hDevice);
bool SendIoctlGetStatus(HANDLE hDevice, AKIR_TIMER_STATUS& status);
bool SendIoctlRegisterProtect(HANDLE hDevice, DWORD pid);
