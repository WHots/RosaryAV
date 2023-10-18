#pragma once
#include <windows.h>


enum class ObjectType : ULONG 
{
    Process = 0,
    Thread = 1,
    File = 2,
    Device = 3,
    Event = 4,
    Mutex = 5,
    Semaphore = 6,
    Timer = 7,
    Port = 8,
    Key = 9,
    Section = 10,
    Job = 11,
    ProcessGroup = 12,
    Directory = 13,
    SymbolicLink = 14,
    Pipe = 15,
    WaitablePort = 16,
    RegistryKey = 17,
    RegistryValue = 18,
    Win32Driver = 19,
    Win32Service = 20,
    Win32Device = 21,
    Win32Process = 22,
    Win32Thread = 23,
    Win32Event = 24,
    Win32Mutex = 25,
    Win32Semaphore = 26,
    Win32Timer = 27,
    Win32Port = 28,
    Win32Key = 29,
    Win32Section = 30,
    Win32Job = 31,
    Win32ProcessGroup = 32,
    Win32Directory = 33,
    Win32SymbolicLink = 34,
    Win32Pipe = 35,
    Win32WaitablePort = 36,
    Win32RegistryKey = 37,
    Win32RegistryValue = 38,
};


typedef struct SYSTEM_HANDLE
{
    ULONG ProcessId;
    UCHAR ObjectTypeNumber;
    UCHAR Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;

} SYSTEM_HANDLE_INFORMATION_, * PSYSTEM_HANDLE_INFORMATION_;

typedef struct SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];

} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;


typedef struct _LDR_MODULE 
{
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID BaseAddress;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;

} LDR_MODULE, * PLDR_MODULE;
