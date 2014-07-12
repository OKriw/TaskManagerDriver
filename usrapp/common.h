#ifndef COMMON_H_
#define COMMON_H_

#define USER_

#include <stdio.h>
#include <assert.h>

#ifdef USER_

#include <windows.h>
#include <ntsecapi.h>

#define USHORT      WORD
#define ULONG       DWORD
#define NT_STATUS   DWORD

#define NT_SUCCESS(status) ((status) >= 0)
#define STATUS_SUCCESS  0

#define log(...) \
    do { \
        printf(__VA_ARGS__); } \
    while (0)
#else
#define log(...) \
    do { \
        DbgPrint(__VA_ARGS__); } \
    while(0)
#endif /* USER_ */


typedef enum _LPC_TYPE {
    LPC_NEW_MESSAGE,    // A new message
    LPC_REQUEST,        // A request message
    LPC_REPLY,          // A reply to a request message
    LPC_DATAGRAM,       //
    LPC_LOST_REPLY,     //
    LPC_PORT_CLOSED,    // Sent when port is deleted
    LPC_CLIENT_DIED,    // Messages to thread termination ports
    LPC_EXCEPTION,      // Messages to thread exception port
    LPC_DEBUG_EVENT,    // Messages to thread debug port
    LPC_ERROR_EVENT,    // Used by ZwRaiseHardError
    LPC_CONNECTION_REQUEST  // Used by ZwConnectPort
} LPC_TYPE;


typedef struct _LPC_MESSAGE_HEADER {
    USHORT   DataLength;
    USHORT   TotalLength;
    USHORT  MessageType;
    USHORT  DataInfoOffset;
    ULONG   ProcessId;
    ULONG   ThreadId;
    ULONG   MessageId;
    ULONG   CallbackId;
} LPC_MESSAGE_HEADER, *PLPC_MESSAGE_HEADER;


typedef struct _LPC_SECTION_MEMORY
{
	ULONG                   Length;
	ULONG                   ViewSize;
	PVOID                   ViewBase;
} LPC_SECTION_MEMORY, *PLPC_SECTION_MEMORY;


typedef struct _LPC_SECTION_OWNER_MEMORY
{
	ULONG                   Length;
	HANDLE                  SectionHandle;
	ULONG                   OffsetInSection;
	ULONG                   ViewSize;
	PVOID                   ViewBase;
	PVOID                   OtherSideViewBase;
} LPC_SECTION_OWNER_MEMORY, *PLPC_SECTION_OWNER_MEMORY;


typedef struct _OBJECT_ATTRIBUTES 
{
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;      
  PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;


/* OBJECT_ATTRIBUTES helper */
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

	
VOID NTAPI RtlInitUnicodeString (PUNICODE_STRING DestinationString, PCWSTR SourceString);


NTSTATUS NTAPI NtCreatePort(
    OUT PHANDLE              PortHandle,
    IN  POBJECT_ATTRIBUTES   ObjectAttributes,
    IN  ULONG                MaxConnectInfoLength,
    IN  ULONG                MaxDataLength,
    IN  ULONG                MaxPoolUsage
);


NTSYSAPI NTSTATUS NTAPI NtReplyWaitReceivePort(
	IN  HANDLE        		PortHandle,
	OUT PVOID*        		PortContext       OPTIONAL,
	IN  PLPC_MESSAGE_HEADER Reply             OPTIONAL,
	OUT PLPC_MESSAGE_HEADER IncomingRequest
); 


NTSYSAPI NTSTATUS NTAPI NtAcceptConnectPort(
    OUT    PHANDLE                   ServerPortHandle,
    IN     PVOID                     PortContext,
    IN     PLPC_MESSAGE_HEADER       ConnectionMsg,
    IN     BOOLEAN                   AcceptConnection,
    IN OUT PLPC_SECTION_OWNER_MEMORY ServerSharedMemory           OPTIONAL,
    OUT    PLPC_SECTION_MEMORY       ClientSharedMemory           OPTIONAL
);


NTSYSAPI NTSTATUS NTAPI NtConnectPort(
    OUT    PHANDLE                      ClientPortHandle,
    IN     PUNICODE_STRING              ServerPortName,
    IN     PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    IN OUT PLPC_SECTION_OWNER_MEMORY    ClientSharedMemory   OPTIONAL,
    OUT    PLPC_SECTION_MEMORY          ServerSharedMemory   OPTIONAL,
    OUT    PULONG                       MaximumMessageLength OPTIONAL,
    IN OUT PVOID                        ConnectionInfo       OPTIONAL,
    IN OUT PULONG                       ConnectionInfoLength OPTIONAL
);


NTSYSAPI NTSTATUS NTAPI NtCompleteConnectPort(
    IN HANDLE               PortHandle
);


NTSYSAPI NTSTATUS NTAPI NtReplyPort(
  IN HANDLE               PortHandle,
  IN PLPC_MESSAGE_HEADER  Reply
);


NTSYSAPI NTSTATUS NTAPI NtRequestWaitReplyPort(
  IN  HANDLE               PortHandle,
  IN  PLPC_MESSAGE_HEADER  Request,
  OUT PLPC_MESSAGE_HEADER  IncomingReply
);


NTSYSAPI NTSTATUS NTAPI NtRequestPort(
  IN HANDLE               PortHandle,
  IN PLPC_MESSAGE_HEADER  Request
);


#endif /* COMMON_H_ */
