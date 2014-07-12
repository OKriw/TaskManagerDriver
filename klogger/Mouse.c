
#include "ntddk.h"
#include "stdarg.h"
#include "stdio.h"
#include "ntddkbd.h"
#include "Ntddmou.h"


#define KEY_UP         1
#define KEY_DOWN       0

#define LCONTROL       ((USHORT)0x1D)
#define CAPS_LOCK      ((USHORT)0x3A)

#define DEFAULT_LOG_FILE_NAME   L"\\??\\c:\\ioman.log"


NTSYSAPI
VOID
NTAPI
HalDisplayString(PCHAR String);

PDEVICE_OBJECT  kbdDevice;
PDEVICE_OBJECT  HookDeviceObject;


NTSTATUS MouseDispatchRead(IN PDEVICE_OBJECT DeviceObject,
        IN PIRP Irp);
NTSTATUS MouseDispatchGeneral(IN PDEVICE_OBJECT DeviceObject,
        IN PIRP Irp);
NTSTATUS MouseDispatchCreate(IN PDEVICE_OBJECT DeviceObject,
        IN PIRP Irp);
NTSTATUS MouseInit(IN PDRIVER_OBJECT DriverObject);



NTSTATUS DriverEntry(
    IN PDRIVER_OBJECT   DriverObject,
    IN PUNICODE_STRING  RegistryPath)
{
    PDEVICE_OBJECT  deviceObject        = NULL;
    NTSTATUS        ntStatus;
    WCHAR           deviceNameBuffer[]  = L"\\Device\\MafMouse";
    UNICODE_STRING  deviceNameUnicodeString;
    WCHAR           deviceLinkBuffer[]  = L"\\DosDevices\\MafMouse";
    UNICODE_STRING  deviceLinkUnicodeString;

    DbgPrint("Mouse.sys: Entering DriverEntry()\n");

    RtlInitUnicodeString(
            &deviceNameUnicodeString,
            deviceNameBuffer);

    ntStatus = IoCreateDevice(
            DriverObject,
            0,
            &deviceNameUnicodeString,
            FILE_DEVICE_CTRL2CAP,
            0,
            TRUE,
            &deviceObject);

    if (NT_SUCCESS(ntStatus)) {
        RtlInitUnicodeString(
                &deviceLinkUnicodeString,
                deviceLinkBuffer);
        ntStatus = IoCreateSymbolicLink(
                &deviceLinkUnicodeString,
                &deviceNameUnicodeString);

        if (!NT_SUCCESS(ntStatus)) {
            DbgPrint("Mouse.sys: IoCreateSymbolicLink failed\n");
        }

        //
        // Create dispatch points for all IRPs
        //

        DriverObject->MajorFunction[IRP_MJ_READ]            = MouseDispatchRead;
        DriverObject->MajorFunction[IRP_MJ_CREATE]          = MouseDispatchCreate;
        DriverObject->MajorFunction[IRP_MJ_CLOSE]           =
        DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS]   =
        DriverObject->MajorFunction[IRP_MJ_CLEANUP]         =
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]
                = MouseDispatchGeneral;


    }

    if (!NT_SUCCESS(ntStatus)) {
        DbgPrint("DriverEntry failed with error code %x\n", ntStatus);
        if (deviceObject) {
            IoDeleteDevice(deviceObject);
        }
    }

    return MouseInit(DriverObject);
}


NTSTATUS MouseInit(IN PDRIVER_OBJECT DriverObject)
{
    CCHAR           ntNameBuffer[64];
    STRING          ntNameString;
    UNICODE_STRING  ntUnicodeString;
    NTSTATUS        status;

    //sprintf(ntNameBuffer, "\\Device\\KeyboardClass0");
    sprintf(ntNameBuffer, "\\Device\\PointerClass0");
    RtlInitAnsiString(&ntNameString, ntNameBuffer);
    RtlAnsiStringToUnicodeString(&ntUnicodeString, &ntNameString, TRUE);

    //
    // Create DeviceObject for the keyboard
    //
    status = IoCreateDevice(
            DriverObject,
            0,
            NULL,
            FILE_DEVICE_UNKNOWN,
            0,
            FALSE,
            &HookDeviceObject);

    if (!NT_SUCCESS(status)) {
        DbgPrint("Ctrl2Cap.sys: Keyboard hook failed to create device!\n");
        RtlFreeUnicodeString(&ntUnicodeString);
        return STATUS_SUCCESS;
    }

    HookDeviceObject->Flags |= DO_BUFFERED_IO;

    status = IoAttachDevice(
            HookDeviceObject,
            &ntUnicodeString,
            &kbdDevice);

    if (!NT_SUCCESS(status)) {
        DbgPrint("Mouse.sys: Connect with keyboard failed!\n");
        IoDeleteDevice(HookDeviceObject);
        RtlFreeUnicodeString(&ntUnicodeString);
        return STATUS_SUCCESS;
    }

    RtlFreeUnicodeString(&ntUnicodeString);

    DbgPrint("Mouse: Successfully connected to keyboard device\n");
    //HalDisplayString("Ctrl2Cap Initialized\n");

    return STATUS_SUCCESS;
}


NTSTATUS MouseReadComplete(
        IN PDEVICE_OBJECT   DeviceObject,
        IN PIRP             Irp,
        IN PVOID            Context)
{
    PIO_STACK_LOCATION      IrpSp;
    PKEYBOARD_INPUT_DATA    KeyData;
    PMOUSE_INPUT_DATA       MouseData;
    DbgPrint("Handle ReadComplete\n");
    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    if (NT_SUCCESS(Irp->IoStatus.Status)) {

        MouseData = Irp->AssociatedIrp.SystemBuffer;


        DbgPrint("Position: (%d, %d)\n", MouseData->LastX, MouseData->LastY);
    }



    /*
    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    if (NT_SUCCESS(Irp->IoStatus.Status)) {
        KeyData = Irp->AssociatedIrp.SystemBuffer;

        DbgPrint("ScanCode: %x ", KeyData->MakeCode);
        DbgPrint("%s\n", KeyData->Flags ? "Up" : "Down");

        if (KeyData->MakeCode == LCONTROL) {
            KeyData->MakeCode = CAPS_LOCK;
        }
    }
    */
    if (Irp->PendingReturned) {
        IoMarkIrpPending(Irp);
    }

    return Irp->IoStatus.Status;
}


NTSTATUS MouseDispatchRead(
        IN PDEVICE_OBJECT   DeviceObject,
        IN PIRP             Irp)
{
    PIO_STACK_LOCATION currentIrpStack  = IoGetCurrentIrpStackLocation(Irp);
    PIO_STACK_LOCATION nextIrpStack     = IoGetNextIrpStackLocation(Irp);

    *nextIrpStack = *currentIrpStack;
    DbgPrint("Dispatch read\n");
    IoSetCompletionRoutine(
            Irp,
            MouseReadComplete,
            DeviceObject,
            TRUE,
            TRUE,
            TRUE);

    return IoCallDriver(kbdDevice, Irp);
}


NTSTATUS MouseDispatchCreate(
        IN PDEVICE_OBJECT   DeviceObject,
        IN PIRP             Irp)
{
    PIO_STACK_LOCATION currentIrpStack  = IoGetCurrentIrpStackLocation(Irp);
    PIO_STACK_LOCATION nextIrpStack     = IoGetNextIrpStackLocation(Irp);
    DbgPrint("Dispatch create\n");
    Irp->IoStatus.Status        = STATUS_SUCCESS;
    Irp->IoStatus.Information   = 0;

    if (DeviceObject == HookDeviceObject) {
        *nextIrpStack = *currentIrpStack;
        return IoCallDriver(kbdDevice, Irp);
    } else {
        return STATUS_SUCCESS;
    }
}


NTSTATUS MouseDispatchGeneral(
        IN PDEVICE_OBJECT   DeviceObject,
        IN PIRP             Irp)
{
    PIO_STACK_LOCATION currentIrpStack  = IoGetCurrentIrpStackLocation(Irp);
    PIO_STACK_LOCATION nextIrpStack     = IoGetNextIrpStackLocation(Irp);
    DbgPrint("Dispatch general\n");
    Irp->IoStatus.Status        = STATUS_SUCCESS;
    Irp->IoStatus.Information   = 0;

    if (DeviceObject == HookDeviceObject) {
        *nextIrpStack = *currentIrpStack;
        return IoCallDriver(kbdDevice, Irp);
    } else {
        return STATUS_SUCCESS;
    }
}

