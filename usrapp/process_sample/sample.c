#include <windows.h>
#include <stdio.h>
#include <conio.h>

#include "Lpc.h"
#include "Common.h"

#define LPC_PORT_NAME L"\\BaseNamedObjects\\TaskmgrLpcPort"
#define TASKMGR_DRIVER_NAME L"\\\\.\\dostaskmgrdriver"

enum {
	DRV_INIT = 0x801,
};
	
#define IOCTL_TASKMGR_INIT \
	CTL_CODE(FILE_DEVICE_UNKNOWN, DRV_INIT, METHOD_BUFFERED, FILE_ANY_ACCESS)
	
#define BUF_SIZE 32

BOOL SendDeviceIoControl(LPCWSTR deviceName, DWORD *handles, DWORD hbSize)
{
    BOOL    bResult;
    HANDLE  hDevice;
    CHAR    pOut[BUF_SIZE];
    DWORD   bytesWritten = 0;
   
    log("Creating device %S\t", deviceName);
    hDevice = CreateFile(
             deviceName,
             GENERIC_READ | GENERIC_WRITE, 0, NULL,
             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        log("FAILED: 0x%x\n", GetLastError());
        return FALSE;
    } else {
        log("SUCCESS\n");
    }

    ZeroMemory(pOut, BUF_SIZE);

    bResult = DeviceIoControl(
        hDevice,
        IOCTL_TASKMGR_INIT,
        handles,
        hbSize,
        pOut,
        BUF_SIZE,
        &bytesWritten,
        (LPOVERLAPPED) NULL
        );
    if (!bResult) {
        log("FAILED: 0x%x\n", GetLastError());
        return FALSE;
    } else {
        log("SUCCESS\n");
        log("Bytes written: %d\n", bytesWritten);
    }
    CloseHandle(hDevice);
    return TRUE;
}

NTSTATUS OnConnRequest(PLPC_MESSAGE request)
{
    log("OnConnRequest() callback\n");
    return 0;
}

NTSTATUS OnRequest(PLPC_MESSAGE request, PLPC_MESSAGE reply)
{
    char msg[] = "1024768 12";
    log("OnRequest() callback\n");
    memcpy(reply->data, msg, strlen(msg));
    reply->header.DataLength = strlen(msg);
    reply->header.TotalLength = strlen(msg) + sizeof(LPC_MESSAGE_HEADER);
    return 0;
}

DWORD WINAPI LpcListenerRoutine(LPVOID lpParameter)
{
    LPC_SERVER_PORT     port;
    NTSTATUS            status = 0;
    port.OnConnRequest = OnConnRequest;
    port.OnRequest = OnRequest;

    log("Start lpc port listening...");

    status = CreateLpcPort((PLPC_PORT) &port, LPC_PORT_NAME);
    if (status) {
        status = AcceptLpcConnect(&port);
    }

    return 0;
}

int main(void)
{
    HANDLE  hChildProcess;
    HANDLE  hPipeOutRd, hPipeOutWr;
    HANDLE  hPipeInRd, hPipeInWr;
    BOOL    status;
    PROCESS_INFORMATION pi;
    STARTUPINFO si = {sizeof(si)};

    HANDLE  hThread;
    DWORD   tid;

    DWORD   dwHandles[2];
    
    wchar_t pCmdLine[128] = {'\0'};
    wchar_t pTmpRdHandle[4] = {'\0'};
    wchar_t pTmpWrHandle[4] = {'\0'};
   
    /* Create pipe for OUT */
    status = CreatePipe(&hPipeOutRd, &hPipeOutWr, NULL, 0);
    if (!status) {
        fprintf(stderr, "Failed to create OUT pipe.\n");
        return 1;
    }

     /* For IN */
    status = CreatePipe(&hPipeInRd, &hPipeInWr, NULL, 0);
    if (!status) {
        fprintf(stderr, "Failed to create IN pipe.\n");
        return 1;
    }

    dwHandles[0] = (DWORD) hPipeOutWr;
    dwHandles[1] = (DWORD) hPipeInRd;
    printf("FOR IOCTL: %d\t%d\n", dwHandles[0], dwHandles[1]);

    /* Handles to utility */
    wcscat(pCmdLine, L"utility");
    wcscat(pCmdLine, L" ");
    wsprintf(pTmpRdHandle, L"%d", hPipeOutRd);
    wcscat(pCmdLine, pTmpRdHandle);
    wcscat(pCmdLine, L" ");
    wsprintf(pTmpWrHandle, L"%d", hPipeInWr);
    wcscat(pCmdLine, pTmpWrHandle);

    printf("SERVER set cmdLine: %S\n", pCmdLine);



    /* Create utility process */
    printf("Creating new process...");
    status = CreateProcess(
        TEXT(".\\utility.exe"),
        pCmdLine,
        NULL,
        NULL,
        TRUE,
        0,
        NULL,
        NULL,
        &si,
        &pi
        );

    printf("SERVER: %x\n", GetLastError());
    hChildProcess = pi.hProcess;
    printf("INFO: %d\n", hChildProcess);
    if (!status) {
        DWORD err = GetLastError();
        printf("Failed: 0x%x\t%d\n", err, err);
        getch();
        return 1;
    }

#if 0
    SendDeviceIoControl(TASKMGR_DRIVER_NAME, dwHandles, 2 * sizeof(DWORD));

#endif

    hThread = CreateThread(
        NULL,
        0,
        LpcListenerRoutine,
        NULL,
        0,
        &tid
        );

    Sleep(2000);


	WaitForSingleObject(hThread, INFINITE);
	getch();
    return 0;
}



    

