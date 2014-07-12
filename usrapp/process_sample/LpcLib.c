#include "Common.h"
#include "LpcLib.h"

#define MAX_CONNECT_INFO_SIZE   0x104

NTSTATUS CreateLpcPort(PLPC_PORT LpcPort, LPCWSTR PortName)
{
    NTSTATUS            status;
    OBJECT_ATTRIBUTES   portAttr;
    UNICODE_STRING      usPortName;
    ULONG               maxDataSize;
    maxDataSize = sizeof(LPC_MESSAGE);
    
    RtlInitUnicodeString(&usPortName, PortName);
    InitializeObjectAttributes(&portAttr, &usPortName, 0, NULL, NULL);

    log("Port Creating...");
    status = NtCreatePort(
        &LpcPort->hPort,
        &portAttr,
        MAX_CONNECT_INFO_SIZE,
        maxDataSize,
        0);
    if (NT_SUCCESS(status)) {
        log("Created port\n");
    } else {
        log("Failed.\nstatus: %x\n", status);
    }
    return status;
}

NTSTATUS AcceptLpcConnect(PLPC_PORT LpcPort, BOOL AcceptConnection, BYTE *reply, WORD replyLength)
{
    NTSTATUS    status;
    LPC_MESSAGE reqMsg, repMsg;
    PSERVER_LPC_PORT   serverPort;
    HANDLE      hPort = INVALID_HANDLE_VALUE;
    PHANDLE     phPort = &hPort;
    BOOL        stopFlag = FALSE;
 
    log("Wait for connection...");
    serverPort = (PSERVER_LPC_PORT) LpcPort;
    
    while (!stopFlag) {
        status = NtReplyWaitReceivePort(
            LpcPort->hPort,
            (PVOID *) &phPort,
            NULL,
            (PLPC_MESSAGE_HEADER) &reqMsg
            );

        log("status: %x\n", status);
        log("Message type: %x\n", reqMsg.header.MessageType);
        switch (reqMsg.header.MessageType) {
        case LPC_CONNECTION_REQUEST:
            status = NtAcceptConnectPort(
                &hPort,
                NULL,
                (PLPC_MESSAGE_HEADER) &reqMsg,
                AcceptConnection,
                NULL,
                NULL
                );

            log("NtAcceptConnectPort: %x\n", status);
            status = NtCompleteConnectPort(hPort);
            log("NtCompleteConnectPort: %x\n", status);
            break;
        case LPC_REQUEST:
        case LPC_DATAGRAM:
            memset(&repMsg, 0, sizeof(repMsg));
            memcpy(&(repMsg.header), &(reqMsg.header), sizeof(repMsg.header));
            memcpy(repMsg.data, reply, replyLength);
            repMsg.header.DataLength = replyLength;
            repMsg.header.TotalLength = replyLength + sizeof(repMsg.header);

            log("SERVER: request: %s\n", reqMsg.data);
            log("SERVER: reply: %s\n", repMsg.data);
            
            status = NtReplyPort(hPort, (PLPC_MESSAGE_HEADER) &repMsg);
            log("NtReplyPort: %x\n", status);
            status = NtCompleteConnectPort(hPort);
            stopFlag = TRUE;
            break;
        case LPC_PORT_CLOSED:
            log("LPC_PORT_CLOSED\n");
            break;
        default:
            break;
        };

    }
    return status;
}


NTSTATUS ConnectLpcPort(PLPC_PORT LpcPort, LPCWSTR PortName)
{
    NTSTATUS        status;
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
        NULL,
        NULL
        );
    LpcPort->flags = 0;

    log("NtConnectPort: %x\n", status);
                                
    return status;
}


NTSTATUS SendLpcMessage(PLPC_PORT ClientPort, BYTE *request, WORD requestLength, BYTE *reply, WORD *replyLength)
{
    LPC_MESSAGE reqMsg, repMsg;
    NTSTATUS    status = 0;
    

    memset(&reqMsg, 0, sizeof(reqMsg));
    reqMsg.header.TotalLength = sizeof(reqMsg.header);
    status = NtRequestWaitReplyPort(ClientPort->hPort, (PLPC_MESSAGE_HEADER) &reqMsg, (PLPC_MESSAGE_HEADER) &repMsg);
    log("NtRequest status: %x\n", status);

    return status;
}
