#include "Common.h"
#include "Lpc.h"

#define MAX_CONNECT_INFO_SIZE   0x104
//#define LPC_PORT_NAME L"\\BaseNamedObjects\\DriverLpcPort"

/* Offset in request message from client to server on Creating Client Port */
#define DATA_OFFSET 0x0

VOID CheckStatus(NTSTATUS status)
{
    if (NT_SUCCESS(status)) {
        log("SUCCESS\n");
        return;
    }
    switch (status) {
    case LPC_REFUSED:
        log("ERROR: LPC connection refused\n");
        break;
    default:
        log("ERROR: 0x%x\n", status);
    }
}

VOID PrintLpcMessageHeader(PLPC_MESSAGE_HEADER msg)
{
    log("LPC_MESSAGE_HEADER:\n");
    log("\tDataLength= %d\n", msg->DataLength);
    log("\tTotalLength= %d\n", msg->TotalLength);
    log("\tMessageType= 0x%x\n", msg->MessageType);
    log("\tProcId= %d\n\tThreadId= %d\n", msg->ProcessId, msg->ThreadId);
}

NTSTATUS CreateLpcPort(PLPC_PORT LpcPort, LPCWSTR PortName)
{
    
    OBJECT_ATTRIBUTES   portAttr;
    UNICODE_STRING      usPortName;
    ULONG               maxDataSize;
    NTSTATUS            status = STATUS_SUCCESS;

    maxDataSize = sizeof(LPC_MESSAGE);
    
    RtlInitUnicodeString(&usPortName, PortName);
    InitializeObjectAttributes(&portAttr, &usPortName, 0, NULL, NULL);

    status = NtCreatePort(
        &LpcPort->hPort,
        &portAttr,
        MAX_CONNECT_INFO_SIZE,
        maxDataSize,
        0);

    log("NtCreatePort %S:\t", PortName);
    CheckStatus(status);

    return status;
}

NTSTATUS AcceptLpcConnect(PLPC_SERVER_PORT LpcPort)
{
    NTSTATUS    status = STATUS_SUCCESS;
    LPC_MESSAGE reqMsg, repMsg;
	BOOLEAN		bAccept;
    HANDLE      hPort = INVALID_HANDLE_VALUE;
    PHANDLE     phPort = &hPort;
    

    memset(&repMsg, 0, sizeof(LPC_MESSAGE));
    memset(&reqMsg, 0, sizeof(LPC_MESSAGE));

    while (1) {
        status = NtReplyWaitReceivePort(
            LpcPort->lpcPort.hPort,
            (PVOID *) &phPort,
            NULL,
            (PLPC_MESSAGE_HEADER) &reqMsg
            );

         log("\n----------------------------------\n");
         log("NtReplyWaitReceivePort:\t");
         CheckStatus(status);
         log("\n----------------------------------\n");

        if (!NT_SUCCESS(status)) {
            return status;
        }

        /* LOG INFORMATION */
        PrintLpcMessageHeader((PLPC_MESSAGE_HEADER) &reqMsg);
        reqMsg.data[reqMsg.header.DataLength] = '\0';
        log("LPC_CONNECT_INFO: %s\n", (reqMsg.data + DATA_OFFSET));
        bAccept = LpcPort->lpcPort.flags & LPC_PORT_ACCEPT_CONNECT;
        
        switch (reqMsg.header.MessageType) {
        case LPC_CONNECTION_REQUEST:
            status = NtAcceptConnectPort(
                &hPort,
                NULL,
                (PLPC_MESSAGE_HEADER) &reqMsg,
                bAccept,
                NULL,
                NULL
                );
            
            if (LpcPort->OnConnRequest) {
                LpcPort->OnConnRequest(&reqMsg);
            }

            log("NtAcceptConnectPort:\t");
            CheckStatus(status);
            status = NtCompleteConnectPort(hPort);
            log("NtCompleteConnectPort:\t");
            CheckStatus(status);
            break;
        case LPC_REQUEST:
            memcpy(&repMsg.header, &reqMsg.header, sizeof(LPC_MESSAGE_HEADER));
            if (LpcPort->OnRequest) {
                LpcPort->OnRequest(&reqMsg, &repMsg);
            }
            status = NtReplyPort(hPort, (PLPC_MESSAGE_HEADER) &repMsg);
            log("NtReplyPort()\n");
            CheckStatus(status);
            break;
        case LPC_DATAGRAM:
            log("LPC_DATAGRAM\n");
        case LPC_PORT_CLOSED:
            log("LPC_PORT_CLOSED\n");
            break;
        default:
            break;
        };

    }
    return status;
}


NTSTATUS ConnectLpcPort(PLPC_PORT LpcPort, LPCWSTR PortName, PVOID ConnectInfo, ULONG ConnectInfoLength)
{
    NTSTATUS        status = STATUS_SUCCESS;
    UNICODE_STRING  usPortName;

    SECURITY_QUALITY_OF_SERVICE securityQos = 
    {
        sizeof(securityQos), SecurityImpersonation, SECURITY_DYNAMIC_TRACKING, TRUE
    };

    RtlInitUnicodeString(&usPortName, PortName);
    log("Connecting to port: %S\n", PortName);
    status = NtConnectPort(
        &LpcPort->hPort,
        &usPortName,
        &securityQos,
        NULL,
        NULL,
        NULL,
        ConnectInfo,
        &ConnectInfoLength
        );
 
    log("NtConnectPort:\t");
    CheckStatus(status);
                                
    return status;
}


NTSTATUS SendLpcMessage(PLPC_PORT ClientPort, PVOID request, USHORT requestLength, PVOID reply, USHORT *replyLength)
{
    LPC_MESSAGE reqMsg, repMsg;
    NTSTATUS    status = STATUS_SUCCESS;
    
    memset(&reqMsg, 0, sizeof(reqMsg));
    reqMsg.header.DataLength = requestLength;
    reqMsg.header.TotalLength = sizeof(reqMsg.header) + requestLength;
    memcpy(reqMsg.data, request, requestLength);

    status = NtRequestWaitReplyPort(ClientPort->hPort, (PLPC_MESSAGE_HEADER) &reqMsg, (PLPC_MESSAGE_HEADER) &repMsg);
    log("NtRequestWaitReply:\t");
    CheckStatus(status);
    if (!NT_SUCCESS(status))
        return status;
    memcpy(reply, repMsg.data, repMsg.header.DataLength);
    *replyLength = repMsg.header.DataLength;

    return status;
}
