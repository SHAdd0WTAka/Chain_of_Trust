#include <ntddk.h>
#include <wdm.h>
#include <initguid.h>
#include <tpm.h>

#define AKIR_DEVICE_NAME L"\\Device\\AKIR_EDR"
#define AKIR_DOS_DEVICE  L"\\DosDevices\\AKIR_EDR"

#define IOCTL_AKIR_RESET_TIMER      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_AKIR_GET_TIMER_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_AKIR_REGISTER_PROTECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_AKIR_UNREGISTER_PROTECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_AKIR_TRIGGER_RECOVERY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_AKIR_GET_STATE        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_READ_ACCESS)

typedef enum _AKIR_SYSTEM_STATE {
    AkirClean       = 0,
    AkirMonitoring  = 1,
    AkirTimerLow    = 2,
    AkirCompromised = 3,
    AkirRecovering  = 4,
    AkirHoneypot    = 5
} AKIR_SYSTEM_STATE;

typedef struct _AKIR_TIMER_STATUS {
    DWORD             RemainingMinutes;
    AKIR_SYSTEM_STATE State;
    DWORD             IntegrityScore;
} AKIR_TIMER_STATUS;

typedef struct _AKIR_PROTECT_REQUEST {
    DWORD  ProcessId;
    WCHAR  ProcessPath[260];
} AKIR_PROTECT_REQUEST;

typedef struct _AKIR_DEVICE_EXTENSION {
    LONG               TimerMinutes;
    AKIR_SYSTEM_STATE  SystemState;
    DWORD              IntegrityScore;
    KSPIN_LOCK         Lock;
    KTIMER             Timer;
    KDPC               Dpc;
    BOOLEAN            TimerActive;
    DWORD              ProtectedPids[64];
    DWORD              ProtectedCount;
} AKIR_DEVICE_EXTENSION;

DRIVER_UNLOAD     DrvUnload;
DRIVER_DISPATCH   DrvCreate;
DRIVER_DISPATCH   DrvClose;
DRIVER_DISPATCH   DrvIoctl;

PVOID g_RegHandle = NULL;
PVOID g_ObRegHandle = NULL;

OB_PREOP_CALLBACK_STATUS ObPreCallback(PVOID context, POB_PRE_OPERATION_INFORMATION info) {
    UNREFERENCED_PARAMETER(context);
    if (info->KernelHandle) return OB_PREOP_SUCCESS;

    PDEVICE_OBJECT devObj = (PDEVICE_OBJECT)context;
    PAKIR_DEVICE_EXTENSION ext = (PAKIR_DEVICE_EXTENSION)devObj->DeviceExtension;

    if (ext->SystemState >= AkirCompromised) {
        return OB_PREOP_SUCCESS;
    }

    if (info->ObjectType == PsProcessType) {
        HANDLE hProc = NULL;
        if (NT_SUCCESS(ObReferenceObjectByPointer(info->Object, 0, *PsProcessType, KernelMode))) {
            DWORD pid = (DWORD)HandleToULong(PsGetCurrentProcessId());
            KeAcquireSpinLockAtDpcLevel(&ext->Lock);
            for (DWORD i = 0; i < ext->ProtectedCount; i++) {
                if (ext->ProtectedPids[i] == pid) {
                    info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
                    break;
                }
            }
            KeReleaseSpinLockFromDpcLevel(&ext->Lock);
            ObDereferenceObject(info->Object);
        }
    }

    return OB_PREOP_SUCCESS;
}

NTSTATUS RegCallback(PVOID context, PVOID arg1, PVOID arg2) {
    UNREFERENCED_PARAMETER(context);
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)arg1;

    if (notifyClass == RegNtPreSetValueKey || notifyClass == RegNtPreDeleteKey) {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)arg2;
        UNICODE_STRING akirPath;
        RtlInitUnicodeString(&akirPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\AKIR_EDR");

        if (info->Object) {
            return STATUS_ACCESS_DENIED;
        }
    }

    return STATUS_SUCCESS;
}

VOID TimerDpcRoutine(_KDPC* dpc, PVOID context, PVOID sysArg1, PVOID sysArg2) {
    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(sysArg1);
    UNREFERENCED_PARAMETER(sysArg2);

    PDEVICE_OBJECT devObj = (PDEVICE_OBJECT)context;
    PAKIR_DEVICE_EXTENSION ext = (PAKIR_DEVICE_EXTENSION)devObj->DeviceExtension;

    InterlockedDecrement(&ext->TimerMinutes);

    LONG currentTimer = ReadULong(&ext->TimerMinutes);
    if (currentTimer <= 0) {
        ext->SystemState = AkirCompromised;
        KeSetEvent(&devObj->DeviceLock, IO_NO_INCREMENT, FALSE);
    }

    LARGE_INTEGER due;
    due.QuadIntPart = -600000000LL;
    KeSetTimer(&ext->Timer, due, &ext->Dpc);
}

NTSTATUS DrvCreate(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DrvClose(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DrvIoctl(PDEVICE_OBJECT dev, PIRP irp) {
    PAKIR_DEVICE_EXTENSION ext = (PAKIR_DEVICE_EXTENSION)dev->DeviceExtension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG info = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_AKIR_RESET_TIMER:
        InterlockedExchange(&ext->TimerMinutes, 1440);
        ext->SystemState = AkirMonitoring;
        status = STATUS_SUCCESS;
        break;

    case IOCTL_AKIR_GET_TIMER_STATUS:
        if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(AKIR_TIMER_STATUS)) {
            PAKIR_TIMER_STATUS out = (PAKIR_TIMER_STATUS)irp->AssociatedIrp.SystemBuffer;
            out->RemainingMinutes = (DWORD)ReadULong(&ext->TimerMinutes);
            out->State = ext->SystemState;
            out->IntegrityScore = ext->IntegrityScore;
            info = sizeof(AKIR_TIMER_STATUS);
            status = STATUS_SUCCESS;
        }
        break;

    case IOCTL_AKIR_REGISTER_PROTECT:
        if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(AKIR_PROTECT_REQUEST)) {
            PAKIR_PROTECT_REQUEST req = (PAKIR_PROTECT_REQUEST)irp->AssociatedIrp.SystemBuffer;
            KeAcquireSpinLockAtDpcLevel(&ext->Lock);
            if (ext->ProtectedCount < 64) {
                ext->ProtectedPids[ext->ProtectedCount++] = req->ProcessId;
            }
            KeReleaseSpinLockFromDpcLevel(&ext->Lock);
            status = STATUS_SUCCESS;
        }
        break;

    case IOCTL_AKIR_UNREGISTER_PROTECT:
        if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(AKIR_PROTECT_REQUEST)) {
            PAKIR_PROTECT_REQUEST req = (PAKIR_PROTECT_REQUEST)irp->AssociatedIrp.SystemBuffer;
            KeAcquireSpinLockAtDpcLevel(&ext->Lock);
            for (DWORD i = 0; i < ext->ProtectedCount; i++) {
                if (ext->ProtectedPids[i] == req->ProcessId) {
                    ext->ProtectedPids[i] = ext->ProtectedPids[--ext->ProtectedCount];
                    break;
                }
            }
            KeReleaseSpinLockFromDpcLevel(&ext->Lock);
            status = STATUS_SUCCESS;
        }
        break;

    case IOCTL_AKIR_TRIGGER_RECOVERY:
        ext->SystemState = AkirRecovering;
        status = STATUS_SUCCESS;
        break;

    case IOCTL_AKIR_GET_STATE:
        if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(DWORD)) {
            PDWORD outState = (PDWORD)irp->AssociatedIrp.SystemBuffer;
            *outState = (DWORD)ext->SystemState;
            info = sizeof(DWORD);
            status = STATUS_SUCCESS;
        }
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

VOID DrvUnload(PDRIVER_OBJECT drv) {
    UNICODE_STRING dosName;
    RtlInitUnicodeString(&dosName, AKIR_DOS_DEVICE);

    if (g_ObRegHandle) {
        ObUnRegisterCallbacks(g_ObRegHandle);
    }

    if (g_RegHandle) {
        CmUnRegisterCallback(g_RegHandle);
    }

    PDEVICE_OBJECT dev = drv->DeviceObject;
    if (dev) {
        PAKIR_DEVICE_EXTENSION ext = (PAKIR_DEVICE_EXTENSION)dev->DeviceExtension;
        if (ext->TimerActive) {
            KeCancelTimer(&ext->Timer);
        }
        IoDeleteDevice(dev);
    }

    IoDeleteSymbolicLink(&dosName);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
    UNREFERENCED_PARAMETER(reg);

    UNICODE_STRING devName, dosName;
    RtlInitUnicodeString(&devName, AKIR_DEVICE_NAME);
    RtlInitUnicodeString(&dosName, AKIR_DOS_DEVICE);

    PDEVICE_OBJECT devObj = NULL;
    NTSTATUS status = IoCreateDevice(drv, sizeof(AKIR_DEVICE_EXTENSION),
        &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &devObj);
    if (!NT_SUCCESS(status)) return status;

    status = IoCreateSymbolicLink(&dosName, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(devObj);
        return status;
    }

    PAKIR_DEVICE_EXTENSION ext = (PAKIR_DEVICE_EXTENSION)devObj->DeviceExtension;
    KeInitializeSpinLock(&ext->Lock);
    ext->TimerMinutes = 1440;
    ext->SystemState = AkirMonitoring;
    ext->IntegrityScore = 100;
    ext->TimerActive = FALSE;
    ext->ProtectedCount = 0;

    KeInitializeDpc(&ext->Dpc, TimerDpcRoutine, devObj);
    KeInitializeTimer(&ext->Timer);

    LARGE_INTEGER due;
    due.QuadIntPart = -600000000LL;
    KeSetTimer(&ext->Timer, due, &ext->Dpc);
    ext->TimerActive = TRUE;

    OB_OPERATION_REGISTRATION obOps[1];
    obOps[0].ObjectType = PsProcessType;
    obOps[0].Operations = OB_OPERATION_HANDLE_CREATE;
    obOps[0].PreOperation = ObPreCallback;
    obOps[0].PostOperation = NULL;
    obOps[0].RegistrationContext = devObj;

    OB_CALLBACK_REGISTRATION obReg;
    obReg.Version = OB_FLT_REGISTRATION_VERSION;
    obReg.OperationRegistrationCount = 1;
    obReg.RegistrationContext = NULL;
    RtlInitUnicodeString(&obReg.Altitude, L"321000");
    obReg.OperationRegistration = obOps;

    status = ObRegisterCallbacks(&obReg, &g_ObRegHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("AKIR: ObRegisterCallbacks failed (0x%X)\n", status));
    }

    status = CmRegisterCallback(RegCallback, NULL, &g_RegHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("AKIR: CmRegisterCallback failed (0x%X)\n", status));
    }

    drv->MajorFunction[IRP_MJ_CREATE] = DrvCreate;
    drv->MajorFunction[IRP_MJ_CLOSE] = DrvClose;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DrvIoctl;
    drv->DriverUnload = DrvUnload;

    KdPrint(("AKIR: Driver loaded - System monitoring active\n"));
    return STATUS_SUCCESS;
}
