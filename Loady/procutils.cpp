#include "procutils.h"




namespace processutils
{

    static inline PEB* PebBaseAddressEx(const HANDLE hProcess)
    {

        if (hProcess == INVALID_HANDLE_VALUE)
            return nullptr;

        ImportUtils utils(GetModuleHandleW(L"ntdll.dll"));

        auto ptrNtQueryInformationProcess = utils.DynamicImporter<prototypes::fpNtQueryInformationProcess>("NtQueryInformationProcess");

        if (!ptrNtQueryInformationProcess)
            return nullptr;

        PROCESS_BASIC_INFORMATION pbi{};

        NTSTATUS status = ptrNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

        if (!NT_SUCCESS(status))
            return nullptr;

        return pbi.PebBaseAddress;
    }


    PVOID GetProcessHeapAddress(const HANDLE hProcess)
    {

        PEB* pebBase = PebBaseAddressEx(hProcess);

        PVOID processHeapAddress = (PVOID)((char*)pebBase + 0x30);
        PVOID processHeap = nullptr;
        SIZE_T bytesRead;

        BOOL preadResult = ReadProcessMemory(hProcess, processHeapAddress, &processHeap, sizeof(processHeap), &bytesRead);
        return (preadResult && bytesRead == sizeof(processHeap)) ? processHeap : nullptr;
    }


    int GetCurrentHandleCount(const int pid, const int type)
    {

        size_t bufferSize = 0;
        std::unique_ptr<SYSTEM_HANDLE_INFORMATION> buffer(new SYSTEM_HANDLE_INFORMATION[bufferSize / sizeof(SYSTEM_HANDLE_INFORMATION)]);

        ImportUtils util(GetModuleHandleW(L"ntdll.dll"));
        auto NtQuerySystemInformation = util.DynamicImporter<prototypes::fpNtQuerySystemInformation>("NtQuerySystemInformation");

        NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(0x10), buffer.get(), 0xffffff, nullptr);

        int count = 0;

        for (size_t i = 0; i < buffer->HandleCount; ++i)
            if (buffer->Handles[i].ProcessId == pid && buffer->Handles[i].ObjectTypeNumber == type)
                ++count;

        return count;
    }


    PTSTR GetProcessSid(const HANDLE hProcess)
    {

        HANDLE hToken = nullptr;
        std::unique_ptr<void, decltype(&CloseHandle)> tokenGuard(hToken, CloseHandle);

        ImportUtils utils(GetModuleHandleW(L"ntdll.dll"));
        auto NtOpenProcessToken = utils.DynamicImporter<prototypes::fpNtOpenProcessToken>("NtOpenProcessToken");

        if (!NT_SUCCESS(NtOpenProcessToken(hProcess, TOKEN_QUERY, &hToken)))
            return nullptr;       

        auto NtQueryInformationToken = utils.DynamicImporter<prototypes::fpNtQueryInformationToken>("NtQueryInformationToken");

        ULONG dwSize = 0;
        NtQueryInformationToken(hToken, TokenUser, NULL, 0, &dwSize);

        auto buffer = std::make_unique<BYTE[]>(dwSize);

        if (!NT_SUCCESS(NtQueryInformationToken(hToken, TokenUser, buffer.get(), dwSize, &dwSize)))
            return nullptr;

        LPTSTR sidString = nullptr;
        std::unique_ptr<TCHAR, decltype(&LocalFree)> sidGuard(sidString, LocalFree);

        if (!ConvertSidToStringSidW(reinterpret_cast<PTOKEN_USER>(buffer.get())->User.Sid, &sidString))
            return nullptr;


        return _tcsdup(sidString);
    }


    int IsTokenPresent(const HANDLE hToken, const wchar_t* privilegeType)
    {
        
        int fail = -1;
        NTSTATUS status;

        ImportUtils utils(GetModuleHandleW(L"ntdll.dll"));
        auto NtPrivilegeCheck = utils.DynamicImporter<prototypes::fpNtPrivilegeCheck>("NtPrivilegeCheck");

        if (!NtPrivilegeCheck)
            return fail;

        LUID luid{};

        if (!LookupPrivilegeValueW(nullptr, privilegeType, &luid))
            return fail;

        PRIVILEGE_SET requiredPrivileges{};
        requiredPrivileges.PrivilegeCount = 1;
        requiredPrivileges.Control = PRIVILEGE_SET_ALL_NECESSARY;

        LUID_AND_ATTRIBUTES privilegeArray[1];
        privilegeArray[0].Luid = luid;
        privilegeArray[0].Attributes = SE_PRIVILEGE_ENABLED;

        requiredPrivileges.Privilege[0] = privilegeArray[0];

        BOOLEAN hasPrivilege;
        status = NtPrivilegeCheck(hToken, &requiredPrivileges, &hasPrivilege);

        return (NT_SUCCESS(status) && hasPrivilege) ? 1 : 0;
    }


    static inline int ThreadStartedSuspended(HANDLE hThread)
    {

        ImportUtils utils(GetModuleHandleW(L"ntdll.dll"));
        auto NtQueryInformationThread = utils.DynamicImporter<prototypes::fpNtQueryInformationThread>("NtQueryInformationThread");

        if (!NtQueryInformationThread)
            return -1;
       

        THREAD_BASIC_INFORMATION tbi{};
        NTSTATUS status = NtQueryInformationThread(hThread, (THREADINFOCLASS)0x00, &tbi, sizeof(tbi), nullptr);

        if (!NT_SUCCESS(status))
            return -1;

        return (tbi.CreateFlags & 0x00000001) ? 1 : 0;
    }


    int GetOldestThreadStartFlag(const int pid)
    {

        HANDLE hMainThread = NULL;
        FILETIME earliestCreationTime{};
        int result = 0;

        HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);

        if (hThreadSnapshot != INVALID_HANDLE_VALUE)
        {
            THREADENTRY32 te32{};
            te32.dwSize = sizeof(THREADENTRY32);

            if (Thread32First(hThreadSnapshot, &te32))
            {
                do
                {
                    if (te32.th32OwnerProcessID == pid)
                    {
                        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);

                        if (hThread)
                        {
                            FILETIME creationTime, exitTime, kernelTime, userTime;

                            if (GetThreadTimes(hThread, &creationTime, &exitTime, &kernelTime, &userTime))
                            {
                                LONG comparisonResult = CompareFileTime(&creationTime, &earliestCreationTime);

                                if (hMainThread == NULL || comparisonResult == -1)
                                {
                                    earliestCreationTime = creationTime;

                                    if (hMainThread)
                                        CloseHandle(hMainThread);

                                    hMainThread = hThread;
                                }                                                               
                            }
                            CloseHandle(hThread);
                        }
                    }
                } while (Thread32Next(hThreadSnapshot, &te32));
            }
            CloseHandle(hThreadSnapshot);
        }

        if (hMainThread)
        {
            result = ThreadStartedSuspended(hMainThread);
            CloseHandle(hMainThread);
        }

        return result;
    }


    int GetHiddenThreadCount(const int pid) 
    {

        HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);

        if (!hThreadSnapshot) 
            return 0;
        

        std::unique_ptr<void, decltype(&CloseHandle)> hThreadSnapshotGuard(hThreadSnapshot, CloseHandle);

        THREADENTRY32 te32{};
        te32.dwSize = sizeof(THREADENTRY32);
        int hiddenThreadCount = 0;

        ImportUtils utils(GetModuleHandleW(L"ntdll.dll"));
        auto NtQueryInformationThread = utils.DynamicImporter<prototypes::fpNtQueryInformationThread>("NtQueryInformationThread");

        if (Thread32First(hThreadSnapshot, &te32)) 
        {
            do 
            {
                if (te32.th32OwnerProcessID == pid) 
                {

                    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);

                    if (hThread) 
                    {                      
                        ULONG threadHidden = 0;
                        NTSTATUS status = NtQueryInformationThread(hThread, (THREADINFOCLASS)17, &threadHidden, sizeof(threadHidden), nullptr);

                        if (NT_SUCCESS(status) && threadHidden) 
                            ++hiddenThreadCount;       

                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hThreadSnapshot, &te32));
        }

        return hiddenThreadCount;
    }


    int GetWriteCount(const HANDLE hProcess)
    {

        ImportUtils utils(GetModuleHandleW(L"ntdll.dll"));
        auto NtQueryInformationProcess = utils.DynamicImporter<prototypes::fpNtQueryInformationProcess>("NtQueryInformationProcess");

        IO_COUNTERS ioCounters{};
        size_t size = 0;
        NTSTATUS status = NtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)2, &ioCounters, sizeof(ioCounters), nullptr);

        if (NT_SUCCESS(status))   
            size = ioCounters.WriteTransferCount;
        

        return (size > 0) ? size / 1024 / 1024 : 0;
    }


    int GetSectionHeader(const HANDLE hProcess, const char* sectionName, PIMAGE_SECTION_HEADER* targetSection) 
    {

        if (!hProcess)        
            return -1;
       

        std::unique_ptr<HMODULE[]> modules(new HMODULE[1]);
        DWORD bytesNeeded;

        if (!K32EnumProcessModules(hProcess, modules.get(), sizeof(modules), &bytesNeeded))
            return -1;

        TCHAR moduleName[MAX_PATH];

        if (!GetModuleFileNameEx(hProcess, modules[0], moduleName, MAX_PATH) || !_tcsstr(moduleName, TEXT(".exe")))
            return -1;

        MODULEINFO moduleInfo{};

        if (!K32GetModuleInformation(hProcess, modules[0], &moduleInfo, sizeof(moduleInfo)))
            return -1;

        PBYTE moduleBase = reinterpret_cast<PBYTE>(moduleInfo.lpBaseOfDll);
        const PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<const PIMAGE_DOS_HEADER>(moduleBase);
        const PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<const PIMAGE_NT_HEADERS>(moduleBase + dosHeader->e_lfanew);

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || ntHeaders->Signature != IMAGE_NT_SIGNATURE) 
            return -1;  

        const PIMAGE_SECTION_HEADER sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);

        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
        {
            if (strncmp((char*)sectionHeaders[i].Name, sectionName, IMAGE_SIZEOF_SHORT_NAME) == 0)
            {
                *targetSection = &sectionHeaders[i];
                return 1;
            }
        }

        return 0;
    }
}