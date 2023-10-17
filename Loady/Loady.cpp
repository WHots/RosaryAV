#include <iostream>
#include "memutils.h"

#include <tlhelp32.h>
#include <sddl.h>
#include "procutils.h"




int main()
{ 

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

    ModuleInfo mainMod = MainModuleEx(GetCurrentProcessId());

    std::wcout << L"Size = " << mainMod.size << std::endl;
    std::wcout << L"Base Address = " << std::hex << mainMod.baseAddress << std::endl;
}