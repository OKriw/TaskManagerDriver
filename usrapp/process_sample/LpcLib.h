#ifndef LPC_WRAPPER_H_
#define LPC_WRAPPER_H_

#include "Common.h"


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

typedef struct _LPC_PORT {
    HANDLE  hPort;
    BYTE    flags;
} LPC_PORT, *PLPC_PORT;

typedef struct _SERVER_LPC_PORT {
	LPC_PORT	lpcPort;
    NTSTATUS (*OnLpcRequest) (PLPC_MESSAGE req, PLPC_MESSAGE rep);
} SERVER_LPC_PORT, *PSERVER_LPC_PORT;	

NTSTATUS CreateLpcPort(PLPC_PORT LpcPort, LPCWSTR PortName);

NTSTATUS AcceptLpcConnect(PLPC_PORT LpcPort, BOOL AcceptConnection, BYTE *reply, WORD replyLength);

NTSTATUS ConnectLpcPort(PLPC_PORT LpcPort, LPCWSTR PortName);

NTSTATUS SendLpcMessage(PLPC_PORT ClientPort, BYTE *request, WORD requestLength, BYTE *reply, WORD *replyLength);


#endif /* LPC_WRAPPER_H_ */