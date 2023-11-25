#include <iostream>
#include "fileutils.h"





struct PLAYER1
{

    LPTSTR sid;
    DWORD pid;
    //  ...
};


int main()
{    
    

    LPTSTR ownerSid = fileutils::GetFileOwnerSid(L"D:\\Window Internals\\Autoruns\\Autoruns64.exe");

    if (ownerSid) {
        std::wcout << L"Owner SID for file " << L": " << ownerSid << std::endl;
        LocalFree(ownerSid); // Free the memory allocated for the SID string
    }
    else {
        std::wcerr << L"Failed to retrieve the file owner's SID." << std::endl;
    }

   /* std::string file = GetFileStemName("D:\\Window Internals\\Autoruns\\Autoruns64.exe");
    std::cout << file <<std::endl;
    GetFileInternalName(L"D:\\Window Internals\\Autoruns\\Autoruns64.exe");
*/

    /*HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());

    LPTSTR test = GetProcessSid(hProcess);
    wprintf(L"%s\n", test);*/
    
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