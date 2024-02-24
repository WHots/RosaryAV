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

        if (!NT_SUCCESS(status))
            return -1;

        int count = 0;

        for (size_t i = 0; i < buffer->HandleCount; ++i)
        {
            if (buffer->Handles[i].ProcessId == pid && buffer->Handles[i].ObjectTypeNumber == type)
                ++count;
        }
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


    inline int ThreadStartedSuspended(HANDLE hThread)
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
                                else
                                    CloseHandle(hThread);
                            }
                            else                           
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


    bool SetTokenPrivilege(const char* privilegeName, bool enable)
    {

        HANDLE hToken{};

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) 
            return false;    

        std::unique_ptr<void, decltype(&CloseHandle)> tokenHandle(hToken, CloseHandle);

        LUID privilegeLuid{};

        if (!LookupPrivilegeValueA(nullptr, privilegeName, &privilegeLuid))
            return false;

        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = privilegeLuid;
        tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

        if (!AdjustTokenPrivileges(tokenHandle.get(), FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
            return false;       

        return true;
    }


    std::vector<SectionInfo> GetSectionInfo(const HANDLE hProcess, const char* sectionName)
    {

        std::vector<SectionInfo> sections{};

        HMODULE hModule = nullptr;
        DWORD cbNeeded = 0;

        if (!EnumProcessModules(hProcess, &hModule, sizeof(hModule), &cbNeeded))
            return sections;

        MODULEINFO moduleInfo{};

        if (!GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo)))
            return sections;

        PBYTE moduleBase = reinterpret_cast<PBYTE>(moduleInfo.lpBaseOfDll);
        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(moduleBase);
        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(moduleBase + dosHeader->e_lfanew);
        auto sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);

        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) 
        {
            char nameBuffer[IMAGE_SIZEOF_SHORT_NAME + 1];
            std::memcpy(nameBuffer, sectionHeaders[i].Name, IMAGE_SIZEOF_SHORT_NAME);
            nameBuffer[IMAGE_SIZEOF_SHORT_NAME] = '\0';

            if (std::strcmp(nameBuffer, sectionName) == 0) 
            {
                SectionInfo section{};
                section.name = nameBuffer;
                section.virtualAddress = sectionHeaders[i].VirtualAddress;
                section.sizeOfRawData = sectionHeaders[i].SizeOfRawData;
                sections.emplace_back(section);
            }
        }

        return sections;
    }


    UCHAR GetProcessSigner(const HANDLE hProcess)
    {

        if (!hProcess)
            return -1;


        ImportUtils utils(GetModuleHandleW(L"ntdll.dll"));
        auto NtQueryInformationProcess = utils.DynamicImporter<prototypes::fpNtQueryInformationProcess>("NtQueryInformationProcess");

        PS_PROTECTION protectionInfo{};
        DWORD returnLength = 0;

        NTSTATUS status = NtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)61, &protectionInfo, sizeof(protectionInfo), &returnLength);

        return (NT_SUCCESS(status)) ? protectionInfo.Signer : -1;
    }
}