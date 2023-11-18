#include "memutils.h"







inline void SecureZero(void* data, size_t size)
{

    volatile char* p = static_cast<volatile char*>(data);

    while (size--)
        *p++ = 0;
}


inline NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded)
{

    unsigned char opcodes[] = "\x4c\x8b\xd1\xb8\x3f\x00\x00\x00\xf6\x04\x25\x08\x03\xfe\x7f\x01\x75\x03\x0f\x05\xc3";
    void* executableMemory = VirtualAlloc(0, sizeof opcodes, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(executableMemory, opcodes, sizeof opcodes);

    prototypes::fpNtReadVirtualMemory NtReadVirtualMemory = reinterpret_cast<prototypes::fpNtReadVirtualMemory>(executableMemory);

    return NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
}


inline void* memmem(const void* haystack, size_t haystack_len, const void* const needle, const size_t needle_len)
{

    if (haystack == NULL) return NULL;
    if (haystack_len == 0) return NULL;
    if (needle == NULL) return NULL;
    if (needle_len == 0) return NULL;

    DWORDLONG offset = 0;

    for (const char* h = (const char*)haystack;
        haystack_len >= needle_len;
        ++h, --haystack_len, ++offset) {
        if (!memcmp(h, needle, needle_len)) {
            return (void*)h;
        }
    }
    return NULL;
}


char* ScanEx(const char* pattern, char* begin, intptr_t size, HANDLE hProc)
{

    char* match{};
    SIZE_T bytesRead;
    DWORD oldprotect;
    char* buffer{};
    MEMORY_BASIC_INFORMATION mbi{};
    mbi.RegionSize = 0x1000;
    NTSTATUS status;

    VirtualQueryEx(hProc, (LPCVOID)begin, &mbi, sizeof(mbi));

    for (char* curr = begin; curr < begin + size; curr += mbi.RegionSize)
    {
        if (!VirtualQueryEx(hProc, curr, &mbi, sizeof(mbi))) 
            continue;

        if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS) 
            continue;

        delete[] buffer;
        buffer = new char[mbi.RegionSize];

        if (VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldprotect))
        {
            status = NtReadVirtualMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, (LPDWORD)&bytesRead);

            if (!NT_SUCCESS(status))         
                return match;

            VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, oldprotect, &oldprotect);
          
            void* result = memmem(buffer, bytesRead, pattern, strlen(pattern));
            if (result != nullptr) 
            {
                match = curr + ((char*)result - buffer);
                break;
            }
        }
    }
    delete[] buffer;
    return match;
}