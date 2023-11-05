#pragma once
#include <windows.h>
#include <winternl.h>


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



typedef struct _THREAD_BASIC_INFORMATION 
{
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    ULONG_PTR CreateFlags;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;

} THREAD_BASIC_INFORMATION;


typedef enum _MEMORY_INFORMATION_CLASS 
{
    MemoryBasicInformation

} MEMORY_INFORMATION_CLASS;


#ifndef NIRSOFT_PEB
#define NIRSOFT_PEB

typedef struct _NIRSOFT_PEB
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    ULONG ImageUsesLargePages : 1;
    ULONG IsProtectedProcess : 1;
    ULONG IsLegacyProcess : 1;
    ULONG IsImageDynamicallyRelocated : 1;
    ULONG SpareBits : 4;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    ULONG CrossProcessFlags;
    ULONG ProcessInJob : 1;
    ULONG ProcessInitializing : 1;
    ULONG ReservedBits0 : 30;
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved[1];
    ULONG SpareUlong;
    //  PPEB_FREE_BLOCK FreeList;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID HotpatchInformation;
    VOID** ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG HeapSegmentReserve;
    ULONG HeapSegmentCommit;
    ULONG HeapDeCommitTotalFreeThreshold;
    ULONG HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    VOID** ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    PRTL_CRITICAL_SECTION LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    WORD OSBuildNumber;
    WORD OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG ImageProcessAffinityMask;
    ULONG GdiHandleBuffer[34];
    PVOID PostProcessInitRoutine;
    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];
    ULONG SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;
    UNICODE_STRING CSDVersion;
    //  _ACTIVATION_CONTEXT_DATA* ActivationContextData;
    //  _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;
    //  _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;
    //  _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;
    ULONG MinimumStackCommit;
    //  _FLS_CALLBACK_INFO* FlsCallback;
    LIST_ENTRY FlsListHead;
    PVOID FlsBitmap;
    ULONG FlsBitmapBits[4];
    ULONG FlsHighIndex;
    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
} NIRSOFT_PEB;

#endif