#include <ntddk.h>

// Note: OB_CALLBACK_REGISTRATION Version definition
#ifndef OB_FLT_REGISTRATION_VERSION
#define OB_FLT_REGISTRATION_VERSION 0x0100
#endif

typedef struct _OB_PRE_OPERATION_INFORMATION *POB_PRE_OPERATION_INFORMATION;

OB_OPERATION_REGISTRATION ops[1];
OB_CALLBACK_REGISTRATION cb = { 0 };
PVOID RegistrationHandle = NULL;

OB_PREOP_CALLBACK_STATUS OnPreOp(PVOID RegCtx, POB_PRE_OPERATION_INFORMATION Info) {
    UNREFERENCED_PARAMETER(RegCtx);
    if (Info->KernelHandle) return OB_PREOP_SUCCESS;
    
    // Logic to block access to protected app would go here
    return OB_PREOP_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
    UNREFERENCED_PARAMETER(reg);
    
    ops[0].ObjectType = PsProcessType;
    ops[0].Operations = OB_OPERATION_HANDLE_CREATE;
    ops[0].PreOperation = OnPreOp;

    cb.Version = OB_FLT_REGISTRATION_VERSION;
    cb.OperationRegistrationCount = 1;
    cb.RegistrationContext = NULL;
    RtlInitUnicodeString(&cb.Altitude, L"321000");
    cb.OperationRegistration = ops;

    return ObRegisterCallbacks(&cb, &RegistrationHandle);
}