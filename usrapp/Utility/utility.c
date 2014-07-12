#include <Windows.h>
#include <stdio.h>
#include <conio.h>

#include "Lpc.h"
#include "Common.h"

#define LPC_PORT_NAME L"\\BaseNamedObjects\\TaskmgrLpcPort1"

int main(int argc, char *argv[])
{
    NTSTATUS    status;
    HANDLE      hPipeOutRd, hPipeInWr;
 
    LPC_PORT    port;

    char    info[] = "Test info";
    DWORD   infoLenfth = strlen(info);
    printf("Connecting server lpc port...\n");
    status = ConnectLpcPort(&port, LPC_PORT_NAME, info, infoLenfth);

#if 0
    char    buffer[128];
    DWORD   numBytesRead = 0;
    log("inite: %d\n", GetLastError());

    sscanf(argv[1], "%d", &hPipeOutRd);
    sscanf(argv[2], "%d", &hPipeInWr);

    printf("Out read handle: %d\n In write handle: %d\n", hPipeOutRd, hPipeInWr);
    log("try to read file: %d\n", GetLastError());
    status = ReadFile(
        hPipeOutRd,
        buffer,
        127 * sizeof(char),
        &numBytesRead,
        NULL
        );

    log("CLIENT: readFile status: %d, %d\n", status, GetLastError());

    buffer[numBytesRead] = '\0';
    log("Utility read from pipe: %s\n", buffer);

#endif

    getch();
    return 0;
}