#include "ntddk.h"
#include "stdio.h"
#include "stdarg.h"

#define STDCALL __stdcall
#define DEFAULT_LOG_FILE_NAME   L"\\??\\c:\\ioman.log"

#if (NTDDI_VERSION >= NTDDI_LONGHORN)
extern NTSYSAPI volatile CCHAR KeNumberProcessors;
#else
#if (NTDDI_VERSION >= NTDDI_WINXP)
extern NTSYSAPI CCHAR KeNumberProcessors;
#else
extern PCCHAR KeNumberProcessors;
#endif
#endif


// Structures
typedef struct _DEVICE_EXTENSION
{
    HANDLE          ThreadHandle;
    KEVENT          StartEvent;
    KEVENT          StopEvent;
    KEVENT          FlushBuffer;
    BOOLEAN         TerminateThread;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

#define MAX_BUFFER_SIZE 10
#define MAX_MESSAGE_SIZE 100

typedef struct _RING_BUFFER
{
    PCHAR   pLogBuf;
    PCHAR   pStart;
    PCHAR   pEnd;
    INT     size;
} RING_BUFFER, *PRING_BUFFER;


// GLOBAL
KEVENT          FlushEvent;
KEVENT          StartEvent;
KEVENT          StopEvent;
KEVENT          WriteEvent;
HANDLE          ThreadHandle;
PETHREAD        pThread;
PRING_BUFFER    pRb;


// Forward
NTSTATUS STDCALL DriverEntry(
        PDRIVER_OBJECT pDriverObject,
        PUNICODE_STRING pusRegPath
        );
        
NTSTATUS STDCALL DriverUnload(PDRIVER_OBJECT pDriverObject);

NTSTATUS KloggerWriteToFile();

VOID Klog(PCHAR pFormat, ...);


#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#endif

NTSTATUS InitRingBuffer(PRING_BUFFER *pRb)
{
    NTSTATUS    status;
    PCHAR       buf;
    
    DbgPrint("klogger.sys: RB Initialization\n");
    *pRb = (PRING_BUFFER) ExAllocatePool(NonPagedPool, sizeof(RING_BUFFER));
    
    if (*pRb == NULL)
        return STATUS_FATAL_APP_EXIT;

    buf = (PCHAR) ExAllocatePool(NonPagedPool, sizeof(CHAR) * MAX_BUFFER_SIZE);
    
    if (buf == NULL)
        return STATUS_FATAL_APP_EXIT;
    
    (*pRb)->pLogBuf = buf;
    (*pRb)->pStart = buf;
    (*pRb)->pEnd = buf;
    (*pRb)->size = MAX_BUFFER_SIZE;
    
    DbgPrint("klogger.sys: RB Initialization ok\n");
    
    return STATUS_SUCCESS;
}

VOID FreeRingBuffer(PRING_BUFFER pRb)
{
    DbgPrint("klogger.sys: RB free\n");
    if (pRb->pLogBuf)
        ExFreePool(pRb->pLogBuf);
    
    if (pRb)
        ExFreePool(pRb);
}

VOID WriteToBufferHelper(PRING_BUFFER pRb, const PCHAR pMsg, ULONG size)
{
    ULONG tail;
    if (size >= pRb->size)
        size = pRb->size-1;
        
    tail = pRb->size - (pRb->pEnd - pRb->pLogBuf);
    
    if (size > tail) {
        RtlCopyMemory(pRb->pEnd, pMsg, tail);
        RtlCopyMemory(pRb->pLogBuf, pMsg + tail, size - tail);
        pRb->pEnd = pRb->pLogBuf + size - tail;
        
        if (pRb->pEnd >= pRb->pStart) {
            pRb->pStart = pRb->pLogBuf + (size - tail + 1) % pRb->size;
        }
    } else {
        RtlCopyMemory(pRb->pEnd, pMsg, size);
        pRb->pEnd += size;
    }
}

VOID WriteToBuffer(
        //PRING_BUFFER  pRb,
        const PCHAR     pMsg,
        ULONG           size
        )
{
    PKSPIN_LOCK     spinLock;
    KIRQL           currentIrql, oldIrql;
    
    KeRaiseIrql(HIGH_LEVEL, &oldIrql);
    KeAcquireSpinLockAtDpcLevel(spinLock, &currentIrql);
    
    bNeedFlush = WriteToBufferHelper(
            pRb,
            pMsg,
            size);
    
    KeReleaseSpinLockFromDpcLevel(spinLock, currentIrql);
    KeLowerIrql(&oldIrql);
    
    if (bNeedFlush)
        if (KeGetCurrentIrql() < 2) {
            KeSetEvent
        } else {
            KeInsertQueuedDpc
        }
}
    
VOID loggerDeferredRoutine( 
        IN PKDPC pthisDpcObject,
        IN PVOID DeferredContext,
        IN PVOID SystemArgument1,
        IN PVOID SystemArgument2
        )
{
    DbgPrint("Print from deffered routine\n");
    
}

VOID SetWriteEvent( 
        IN PKDPC pthisDpcObject,
        IN PVOID DeferredContext,
        IN PVOID SystemArgument1,
        IN PVOID SystemArgument2
        )
{
    DbgPrint("Set write event from deferred routine\n");
    KeSetEvent(&WriteEvent, 0, FALSE);
    
}

VOID SetFlushEvent( 
        IN PKDPC pthisDpcObject,
        IN PVOID DeferredContext,
        IN PVOID SystemArgument1,
        IN PVOID SystemArgument2
        )
{
    DbgPrint("Set event from deferred routine\n");
    KeSetEvent(&FlushEvent, 0, FALSE);
}


VOID TestThread(IN PVOID Context)
{
    KIRQL       currentIrql, oldIrql;
    NTSTATUS    status = STATUS_SUCCESS;
    PKDPC       pDpc;
    PKTIMER     pTimer;
    
    LARGE_INTEGER   timeout, maxTimeout;
    timeout.QuadPart = -12000 * 10000; // 12 sec
    maxTimeout.QuadPart = -20000 * 10000;
    
    DbgPrint("\nTEST THREAD started\n");
    
    // Initialize timer
    pTimer = (PKTIMER) ExAllocatePool(NonPagedPool, sizeof(KTIMER));
    KeInitializeTimerEx(pTimer, SynchronizationTimer);
    KeSetTimer(pTimer, timeout, NULL);
    
    
    pDpc = (PKDPC) ExAllocatePool(NonPagedPool,sizeof(KDPC));
    KeInitializeDpc(pDpc, SetWriteEvent, NULL);
    
    // wait for timer   
    KeWaitForSingleObject(
            pTimer,
            Executive,
            KernelMode,
            FALSE,
            &maxTimeout);
            
    DbgPrint("TestThread: set flush event\n");  
    
    KeRaiseIrql(PROFILE_LEVEL, &oldIrql);
    
    currentIrql = KeGetCurrentIrql();
    
    //WriteToBuffer(pRb, "some", 4);
    DbgPrint("Current irql %d\n", currentIrql);
    
    if (currentIrql == PASSIVE_LEVEL) {
        KeSetEvent(&FlushEvent, 0, FALSE);
    } else {
        KeInsertQueueDpc(pDpc, NULL, NULL);
    }
    
    KeLowerIrql(&oldIrql);
    PsTerminateSystemThread(status);
}

VOID IOThread(IN PVOID Context)
{
    KIRQL           currentIrql, oldIrql;
    LARGE_INTEGER   timeout, maxTimeout;
    NTSTATUS        status = STATUS_SUCCESS;
    PRING_BUFFER    pRb;
    const PCHAR     pMsg = "message1";
    ULONG           size = 8;
    INT_PTR         state;
    PKTIMER         pTimer;
    LONG            interval;
    
    PVOID           pObjects[3]; // wait for
    
    KeSetEvent(&StartEvent, 0, FALSE);
    
    timeout.QuadPart = -6000 * 10000; // 10 sec
    interval = 20000; // 5 sec
    maxTimeout.QuadPart = -20000 * 10000;
    
    InitRingBuffer(&pRb);
    
    state = (INT_PTR) ExAllocatePool(NonPagedPool, sizeof(INT));    
    
    // Set timer for periodic flush
    pTimer=(PKTIMER) ExAllocatePool(NonPagedPool, sizeof(KTIMER));
    KeInitializeTimerEx(pTimer, SynchronizationTimer);
    KeSetTimerEx(pTimer, timeout, interval, NULL);
    
    
    pObjects[0] = pTimer;               // periodic timer
    pObjects[1] = &StopEvent;           // stop flush loop
    pObjects[2] = &FlushEvent;          // do flush, buffer is full
    
    // Flush loop
    while (status != STATUS_WAIT_1) {
        status = KeWaitForMultipleObjects(
                3,
                pObjects,
                WaitAny,
                Executive,
                KernelMode,
                FALSE,
                &maxTimeout,
                NULL);
            
        if (status == STATUS_WAIT_0) {
            DbgPrint("Timer flush\n");
        } else if (status == STATUS_WAIT_2) {
            DbgPrint("RB flush\n");
        } else if (status == STATUS_TIMEOUT) {
            DbgPrint("Timeout delay\n");
            break;
        }
        
        KloggerWriteToFile();
    }
    
    DbgPrint("klogger.sys: IOThread get stop signal\n");
    
    // Free resources
    KeCancelTimer(pTimer);
    ExFreePool(pTimer);
    FreeRingBuffer(pRb);
    
    PsTerminateSystemThread(status);
    
}

NTSTATUS STDCALL DriverEntry(
    PDRIVER_OBJECT pDriverObject,
    PUNICODE_STRING pusRegPath
    )
{
    NTSTATUS        status = STATUS_SUCCESS;
    LARGE_INTEGER   timeout;
    HANDLE          TestThreadHandle;
        
    // Initialize events
    KeInitializeEvent(&StartEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&StopEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&FlushEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&WriteEvent, SynchronizationEvent, FALSE);
    
    // Create worker thread
    status = PsCreateSystemThread(
            &ThreadHandle,
            THREAD_ALL_ACCESS,
            NULL,
            NULL,
            NULL,
            IOThread,
            NULL);
            
    DbgPrint("klogger.sys: Status: %x\n", status);
    
    // get reference
    if (NT_SUCCESS(status)) {
        status = ObReferenceObjectByHandle(
                ThreadHandle,
                FILE_ANY_ACCESS,
                NULL,
                KernelMode,
                (PVOID *) &pThread,
                NULL);
                
        DbgPrint("klogger.sys: Status: %x\n", status);
    }
    
    timeout.QuadPart = 5 * 10000000;
    
    // wait while thread start
    status = KeWaitForSingleObject(
            &StartEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout);
    
    DbgPrint("klogger.sys: (DriverEntry) Wait for Thread started status %d\n", status);
    
    status = PsCreateSystemThread(
            &TestThreadHandle,
            THREAD_ALL_ACCESS,
            NULL,
            NULL,
            NULL,
            TestThread,
            NULL);
    
    return STATUS_SUCCESS;
}


NTSTATUS STDCALL DriverUnload(PDRIVER_OBJECT pDriverObject)
{
    KeSetEvent(&StopEvent, 0, FALSE);
    
    KeWaitForSingleObject(
            &pThread,
            Executive,
            KernelMode,
            FALSE,
            NULL);
            
    DbgPrint("klogger.sys: wait for single object(handle) - ok\n");      
            
    ObDereferenceObject(pThread);
    ZwClose(ThreadHandle);
    
    DbgPrint("klogger.sys: Driver unloaded\n");
    
    return STATUS_FATAL_APP_EXIT;
    
}

NTSTATUS KloggerWriteToFile()
{
    HANDLE              fileHandle;
    IO_STATUS_BLOCK     ioStatus;
    OBJECT_ATTRIBUTES   objectAttributes;
    UNICODE_STRING      fileNameUnicodeString;
    NTSTATUS            status;
    UNICODE_STRING      fileName;
    
    fileName.Buffer = NULL;
    fileName.Length = 0;
    fileName.MaximumLength = sizeof(DEFAULT_LOG_FILE_NAME) + sizeof(UNICODE_NULL);
    fileName.Buffer = ExAllocatePool(PagedPool, fileName.MaximumLength);

    RtlZeroMemory(fileName.Buffer, fileName.MaximumLength);
    status = RtlAppendUnicodeToString(&fileName, (PWSTR) DEFAULT_LOG_FILE_NAME);
    
    InitializeObjectAttributes(
            &objectAttributes,
            (PUNICODE_STRING) &fileName,
            OBJ_CASE_INSENSITIVE,
            NULL,
            NULL);
            
    //in init
    status = ZwCreateFile(
            &fileHandle,
            FILE_APPEND_DATA,
            &objectAttributes,
            &ioStatus,
            0,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_WRITE,
            FILE_OPEN_IF,
            FILE_SYNCHRONOUS_IO_ALERT,
            NULL,
            0);
            
    if (NT_SUCCESS(status)) {
        CHAR            buf[300];
        LARGE_INTEGER   time;
        TIME_FIELDS     timefields;
        ULONG           length;
        
        KeQuerySystemTime(&time);
        ExSystemTimeToLocalTime(&time, &time);
        RtlTimeToTimeFields(&time, &timefields);
        
        sprintf(buf,
                "%2u:%2u:%2u %3ums\n",
                timefields.Hour,
                timefields.Minute,
                timefields.Second,
                timefields.Milliseconds);
                
        length = strlen(buf);
        
        ZwWriteFile(
                fileHandle,
                NULL,
                NULL,
                NULL,
                &ioStatus,
                buf,
                length,
                NULL,
                NULL);
        
        ZwClose(fileHandle);
    }
    
    if (fileName.Buffer) {
        ExFreePool(fileName.Buffer);
    }
}

VOID Klog(PCHAR pFormat, ...)
{
    
    NTSTATUS    status;
    CHAR        buf[MAX_MESSAGE_SIZE];
    va_list     argptr;
    
    KeWaitForSingleObject(
            &WriteEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL);
    
    va_start(argptr, pFormat);
    vsprintf(buf, pFormat, argptr);
    va_end(argptr);
    
    DbgPrint("Buf length = %d\n", strlen(buf));
    
    WriteToBuffer(pRb, "some", 4);
    
}
    
