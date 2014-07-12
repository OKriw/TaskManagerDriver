#include <conio.h>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

#define LOAD_LIBRARY_NAME "LoadLibraryA"

DWORD FindIndexByName(HANDLE hProcess, DWORD ba, DWORD AddressOfNames, DWORD count, const char *name);

DWORD GetProcedureAddress(HANDLE hProcess, DWORD ba, const char* module_name, const char *procedureName)
{
    IMAGE_DOS_HEADER dosHdr;
    IMAGE_NT_HEADERS ntHdr;
    IMAGE_EXPORT_DIRECTORY exports;
    BOOL    status;

    ZeroMemory(&dosHdr, sizeof(IMAGE_DOS_HEADER));
    ZeroMemory(&ntHdr, sizeof(IMAGE_NT_HEADERS));
    ZeroMemory(&exports, sizeof(IMAGE_EXPORT_DIRECTORY));

    status = ReadProcessMemory(
       hProcess,
       (LPVOID) ba,
       &dosHdr, 
       sizeof(dosHdr),
       NULL
       );
       
    if (!status) {
        printf("ReadProcessMemory failed\n");
        return 0;
    }

    if (dosHdr.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid DOS header\n");
        return 0;
    }

    status = ReadProcessMemory(
        hProcess,
        (LPVOID) (ba + dosHdr.e_lfanew),
        &ntHdr,
        sizeof(ntHdr),
        NULL
        );

    if (!status) {
        printf("ReadProcessMemory failed: 0x%x\n", GetLastError());
        return 0;
    } else if (ntHdr.Signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid NT signature\n");
        return 0;
    } 
    // Read export section offset
    DWORD export_offset = ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    status = ReadProcessMemory(
        hProcess,
        (LPVOID) (ba + export_offset),
        &exports,
        sizeof(exports),
        NULL
        );

    if (!status) {
        printf("Failed to ReadProcessMemory: %x\n", GetLastError());
        return 0;
    }

    // Verify that this library is required dll
    char *dllNameBuf = (char *) (ba + exports.Name);
    printf("DLL name: %s\n", dllNameBuf);
    if (strstr(module_name, dllNameBuf) == NULL) {
        return 0;
    }


    DWORD index = FindIndexByName(hProcess, ba, exports.AddressOfNames, exports.NumberOfFunctions, procedureName);
    if (index < 0) {
        printf("Failed to get function name index\n");
        return 0;
    } else {
        printf("Index of %s: %d\n", procedureName, index);
    }

    WORD funcIndex = -1;
    status = ReadProcessMemory(
        hProcess,
        (LPVOID) (ba + exports.AddressOfNameOrdinals + index * sizeof(WORD)),
        &funcIndex,
        sizeof(funcIndex),
        NULL
        );
    if (!status) {
        printf("Failed to ReadProcessMemory: %x\n", GetLastError());
        return 0;
    }

    if ((funcIndex < 0) || (funcIndex >= exports.NumberOfFunctions)) {
        return 0;
    }

    DWORD funcRVA;

    status = ReadProcessMemory(
        hProcess,
        (LPVOID) (ba + exports.AddressOfFunctions + funcIndex * sizeof(DWORD)),
        &funcRVA,
        sizeof(funcRVA),
        NULL
        );
    if (!status) {
        printf("Failed to ReadProcessMemory: %x\n", GetLastError());
        return 0;
    }
    printf("Address Of %s: 0x%08x\n", procedureName, (ba + funcRVA));
        
    
    return (ba + funcRVA);
}

DWORD FindIndexByName(HANDLE hProcess, DWORD ba, DWORD AddressOfNames, DWORD count, const char *name)
{
    BOOL    status;
    // Find Index of function by name
    int size = lstrlenA(name) + 1;
    for (DWORD i = 0; i < count; i++) {
        DWORD nameRVA;
        status = ReadProcessMemory(
            hProcess,
            (LPVOID) (ba + AddressOfNames + i * sizeof(DWORD)),
            &nameRVA,
            sizeof(nameRVA),
            NULL
            );

        if (!status) {
            printf("Failed to ReadProcessMemory: %x\n", GetLastError());
            return -1;
        }

        char func_name_buf[32];
        ReadProcessMemory(
            hProcess,
            (LPVOID) (ba + nameRVA),
            func_name_buf,
            32,
            NULL
            );

        if (!status) {
            printf("Failed to ReadProcessMemory: %x\n", GetLastError());
            return -1;
        } else {
            if (strcmp(func_name_buf, name) == 0) {
                printf("func: %s\n", func_name_buf);
                printf("Index = %d\n", i);
                return i;
            }
        }

    }
    return -1;
}

void InjectCode(HANDLE hProcess, DWORD addr);

#pragma warning(disable:4200)
#pragma pack(push,1)
typedef struct _SHELL_CODE {
    char op_int3_1; //0
    char op_push; //1
    DWORD arg_push; 
    char op_call_1; //6
    DWORD arg_call_1;
    char op_call_2; //11
    DWORD arg_call_2;
    char op_int3_2; //16
    char op_ret; //17
    WORD arg_ret;
    char lib_name[0]; //20
} SHELL_CODE, *PSHELL_CODE;
#pragma pack(pop)
#pragma warning(default:4200)

#define FIELD_OFFSET(T,f) ((DWORD)(&(((T*)0)->f)))

void InitShellCode(PSHELL_CODE p, DWORD remoteAddr, DWORD procAddr, DWORD procAddr2, char* libname)
{
    p->op_int3_1 = p->op_int3_2 = 0xCC;
    p->op_call_1 = p->op_call_2 = 0xE8;
    p->op_push = 0x68;
    p->op_ret = 0xC2;
    p->arg_push = remoteAddr + FIELD_OFFSET(SHELL_CODE,lib_name);
    p->arg_call_1 = procAddr - remoteAddr - FIELD_OFFSET(SHELL_CODE,op_call_2);
    p->arg_call_2 = procAddr2 - remoteAddr - FIELD_OFFSET(SHELL_CODE,op_int3_2);
    p->arg_ret = 0x4;
    memcpy(p->lib_name,libname,strlen(libname)+1);
}

DWORD GetRemoteModule(HANDLE hRemoteProcess, char* module_name)
{
    MEMORY_BASIC_INFORMATION    mbi;
    MEMORY_BASIC_INFORMATION    mbiRem;
    PBYTE   pb = NULL;
    DWORD   numBytes = 0;

    ZeroMemory(&mbi, sizeof(mbi));
    ZeroMemory(&mbiRem, sizeof(mbiRem));

    while (pb <= (PBYTE) 0x7fffffff) {
        if (VirtualQueryEx(hRemoteProcess, pb, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            pb += mbi.RegionSize;
            continue;
        }
        int     nLen;
        char    szModName[MAX_PATH];

        if (mbi.State == MEM_FREE)
            mbi.AllocationBase = mbi.BaseAddress;
        if ((mbi.AllocationBase != mbi.BaseAddress) || (mbi.AllocationBase == NULL)) {
            nLen = 0;
        } else {
            nLen = GetModuleFileNameA((HINSTANCE) mbi.AllocationBase, szModName, MAX_PATH);
        }
        
        if (nLen > 0) {
            printf("0x%08x\t%s\n", mbi.AllocationBase, szModName);
            if (strstr(szModName, module_name)) {
                return (DWORD) mbi.BaseAddress;
            }
        }
        pb += mbi.RegionSize;
    }
    return 0;
}


int main(int argc, char *argv[])
{
#if 1

    HANDLE  hProcess;
    DWORD   procAddr, procAddr2;
    DWORD   procId;

    if (argc < 2) {
        printf("Current process\n");
        procId = (DWORD) GetCurrentProcessId();
    } else {
        printf("Process: %s\n", argv[1]);
        procId = atoi(argv[1]);
    }

    hProcess = OpenProcess(
        PROCESS_CREATE_THREAD |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE,
        procId);

    if (hProcess == NULL)
        return 1;

    DWORD pKernel32 = GetRemoteModule(hProcess, "kernel32.dll");
    DWORD pNtdll = GetRemoteModule(hProcess, "ntdll.dll");

    if ((!pKernel32)||(!pNtdll))
        return 1;

    procAddr = GetProcedureAddress(hProcess, pKernel32, "KERNEL32.dll", LOAD_LIBRARY_NAME);
    procAddr2 = GetProcedureAddress(hProcess, pNtdll, "ntdll.dll", "RtlGetLastWin32Error");
    printf("LoadLibraryA:\t0x%08x\nRtlGetLastWin32Error:\t0x%08x\n", procAddr, procAddr2);
    if ((procAddr == 0)||(procAddr2 == 0)) {
        
        return 1;
    }


    printf("Trying to inject...\n");

//    HMODULE hModule = LoadLibraryW(L"kernel32.dll");
#endif
    

#define THREAD_ALLOC_SIZE 4096

    LPVOID pRemote = VirtualAllocEx(
        hProcess,
        NULL,
        THREAD_ALLOC_SIZE,
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
        );
    if (pRemote == NULL) {
        printf("Failed to allocate memory in remote process: %x\n", GetLastError());
        goto exit;
    }

    char libName[] = "c:\\111\\dll.dll";

    printf("lib_name:\t%d\nop_call_2:\t%d\nop_ret:\t%d\n", FIELD_OFFSET(SHELL_CODE,lib_name),
    FIELD_OFFSET(SHELL_CODE,op_call_2),
    FIELD_OFFSET(SHELL_CODE,op_ret));
     /*
    // Copy string to remote process address space
    if (!WriteProcessMemory(hProcess, (LPVOID) ((DWORD) pRemote + 13), (PVOID) libName, sizeof(libName), NULL)) {
        printf("Failed to write in remote process libName: %x\n", GetLastError());
        goto exit;
    }
   
    DWORD tmp = (DWORD) pRemote + 18;

    DWORD call_addr = procAddr - (DWORD) pRemote - 11;
    printf("Call Addr: 0x%08x\n", call_addr);

    DWORD call_addr2 = procAddr2 - (DWORD) pRemote - 16;
    printf("Call Addr: 0x%08x\n", call_addr);

    //pRemote+6 : call call_addr
    // dest_addr = pRemote + 11 + call_addr = procAddr;

    char code[] = {
        0xcc,                           // int3
        0x68, tmp & 0xff, tmp >> 8 & 0xff, tmp >> 16 & 0xff, tmp >> 24 & 0xff ,   // push
        0xe8, call_addr & 0xff, call_addr >> 8 & 0xff, call_addr >> 16 & 0xff, call_addr >> 24 & 0xff ,   // call
        0xe8, call_addr2 & 0xff, call_addr2 >> 8 & 0xff, call_addr2 >> 16 & 0xff, call_addr2 >> 24 & 0xff ,
        0xcc,
        0xc2, 0x04,                     // ret
    };
    */

    char code[256];
    InitShellCode((PSHELL_CODE)code, (DWORD) pRemote, procAddr, procAddr2, libName);

    __debugbreak();
    LoadLibraryA(libName);

    // Write inject code
    if (!WriteProcessMemory(hProcess, pRemote, code, sizeof(code), NULL)) {
        printf("Failed to write in remote process code: %x\n", GetLastError());
        goto exit;
    }

    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL, 
        0,
        (LPTHREAD_START_ROUTINE) pRemote,
        NULL,
        0,
        NULL
        );
    if(hThread == NULL) {
        printf("Failed to CreateRemoteThread: %x\n", GetLastError());
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);
exit:
    printf("Freeing resources...\n");
    if (pRemote)
        VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
    if (hThread)
        CloseHandle(hThread);
    if (hProcess)
        CloseHandle(hProcess);

      
    getch();
    return 0;
}

void InjectCode(HANDLE hProcess, DWORD addr)
{


}
