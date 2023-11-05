
#include <iostream>
#include "procutils.h"

//#include "memutils.h"
//#include <winternl.h>
//#include <windows.h>
//#include "pointers.hpp"
//#include <tlhelp32.h>
//#include <sddl.h>
//#include "procutils.h"



//struct ProcessTarget
//{
//    ModuleInfo mainModule;
//    int tokenCount;
//    bool startedSuspended;
//    int susHandleCounts;
//};


int main()
{    

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
    PVOID heapAddress = GetProcessHeapAddress(hProcess);

    if (heapAddress == nullptr)
    {
        std::cout << "fails " << std::endl;
    }
    else
    {
        std::cout << "Heap Address: 0x" << std::hex << reinterpret_cast<std::uintptr_t>(heapAddress) << std::dec << std::endl;
    }
    //PEB* pebBase = PebBaseAddress(hProcess);

    //PVOID processHeapAddress = (PVOID)((char*)pebBase + 0x30);

    //PVOID processHeap;
    //SIZE_T bytesRead;
    //if (!ReadProcessMemory(hProcess, processHeapAddress, &processHeap, sizeof(processHeap), &bytesRead)) {
    //    return 1;
    //}

    //std::cout << "Process Heap Address: " << processHeap << std::endl;

    
   //  ProcessInfoQueryGeneric();
    /*HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 11740);
    const char* pattern = "\x45\x8B\xC1\x85\xC9";
    const char* mask = "xxxxx";
    char* matchAddress = ScanEx(pattern, mask, (char*)0x7ff67c3e0000, 10048, hProc);

    if (matchAddress != nullptr) {
        std::cout << "Pattern found at address: 0x" << std::hex << (uintptr_t)matchAddress << std::endl;
    }
    else {
        std::cout << "Pattern not found." << std::endl;
    }
    */

    //DWORD pid = 1234;  // Replace with the process ID you want to query.

    /*ModuleInfo mainMod = MainModuleInfoEx(GetCurrentProcessId());

    std::wcout << L"Size = " << mainMod.size << std::endl;
    std::wcout << L"Base Address = " << std::hex << mainMod.baseAddress << std::endl;*/
}