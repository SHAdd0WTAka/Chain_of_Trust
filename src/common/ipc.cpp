#include "ipc.hpp"
#include <iostream>

bool OpenAKIRDevice(HANDLE& hDevice) {
    hDevice = CreateFileW(AKIR_DOS_DEVICE, GENERIC_WRITE | GENERIC_READ,
        FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "[IPC] Cannot open AKIR device. Is driver loaded?" << std::endl;
        return false;
    }
    return true;
}

void CloseAKIRDevice(HANDLE hDevice) {
    if (hDevice && hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
    }
}

bool SendIoctlResetTimer(HANDLE hDevice) {
    DWORD bytesReturned = 0;
    return DeviceIoControl(hDevice, IOCTL_AKIR_RESET_TIMER,
        NULL, 0, NULL, 0, &bytesReturned, NULL) != FALSE;
}

bool SendIoctlGetStatus(HANDLE hDevice, AKIR_TIMER_STATUS& status) {
    DWORD bytesReturned = 0;
    return DeviceIoControl(hDevice, IOCTL_AKIR_GET_TIMER_STATUS,
        NULL, 0, &status, sizeof(status), &bytesReturned, NULL) != FALSE;
}

bool SendIoctlRegisterProtect(HANDLE hDevice, DWORD pid) {
    AKIR_PROTECT_REQUEST req = { 0 };
    req.ProcessId = pid;
    DWORD bytesReturned = 0;
    return DeviceIoControl(hDevice, IOCTL_AKIR_REGISTER_PROTECT,
        &req, sizeof(req), NULL, 0, &bytesReturned, NULL) != FALSE;
}
