#ifndef LPC_WRAPPER_H_
#define LPC_WRAPPER_H_

#include "Common.h"

#define LPC_REFUSED 0xc0000041


#define DATA_SIZE   50

typedef struct _LPC_MESSAGE {
	LPC_MESSAGE_HEADER	header;
	BYTE			    data[DATA_SIZE];
} LPC_MESSAGE, *PLPC_MESSAGE;

typedef struct _LPC_TERMINATION_MESSAGE
{
  LPC_MESSAGE_HEADER      Header;
  LARGE_INTEGER           CreationTime;
} LPC_TERMINATION_MESSAGE, *PLPC_TERMINATION_MESSAGE;

/* LPC_PORT_COMMUNICATION */

#define LPC_PORT_ACCEPT_CONNECT (1 << 0) /* Acepting connection flag */
#define LPC_PORT_TARGET_PROCESS (1 << 1) /* Accept only target process */
#define LPC_PORT_USING_BUFFER   (1 << 2) /* Use port buffer to set reply msg */



typedef struct _LPC_OPS {
    NTSTATUS (*ObConnRequest) (PLPC_MESSAGE req);
	NTSTATUS (*OnRequest) (PLPC_MESSAGE req, PLPC_MESSAGE rep);
} LPC_OPS, *PLPC_OPS;

typedef struct _LPC_PORT {
    HANDLE  hPort;
    ULONG    flags;
} LPC_PORT, *PLPC_PORT;

typedef struct _LPC_SERVER_PORT {
	LPC_PORT	lpcPort;
    PVOID       pBuf;
    ULONG       bufLength;
    ULONG       targetProcId;
	NTSTATUS (*OnConnRequest) (PLPC_MESSAGE req);
	NTSTATUS (*OnRequest) (PLPC_MESSAGE req, PLPC_MESSAGE rep);
} LPC_SERVER_PORT, *PLPC_SERVER_PORT;	

NTSTATUS CreateLpcPort(PLPC_PORT LpcPort, LPCWSTR PortName);

NTSTATUS AcceptLpcConnect(PLPC_SERVER_PORT LpcPort);

NTSTATUS ConnectLpcPort(PLPC_PORT LpcPort, LPCWSTR PortName, PVOID ConnectInfo, ULONG ConnectInfoLength);

NTSTATUS SendLpcMessage(PLPC_PORT ClientPort, PVOID request, USHORT requestLength, PVOID reply, USHORT *replyLength);

VOID PrintLpcMessageHeader(PLPC_MESSAGE_HEADER msg);

VOID CheckStatus(NTSTATUS status);

#endif /* LPC_WRAPPER_H_ */