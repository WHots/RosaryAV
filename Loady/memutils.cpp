#include "memutils.h"






inline std::byte* MemoryUtils::memmem(std::byte* haystack, size_t haystack_len, const void* needle, size_t needle_len) 
{

    if (!haystack || haystack_len == 0 || !needle || needle_len == 0)
        return nullptr;
    

    for (std::byte* h = haystack; haystack_len >= needle_len; ++h, --haystack_len)
        if (!std::memcmp(h, needle, needle_len)) 
            return h;
        

    return nullptr;
}


inline NTSTATUS MemoryUtils::NtReadVirtualMemory(const HANDLE processHandle, const PVOID baseAddress, const PVOID buffer, const size_t size, size_t* bytesRead) const
{

    static const unsigned char opcodes[] =
    {
      0x4c, 0x8b, 0xd1, 0xb8, 0x3f, 0x00, 0x00, 0x00,
      0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe, 0x7f, 0x01,
      0x75, 0x03, 0x0f, 0x05, 0xc3
    };

    void* executableMemory = VirtualAlloc(0, sizeof(opcodes), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (executableMemory)
        memcpy(executableMemory, opcodes, sizeof(opcodes));
    else
        return 0;

    auto NtReadVirtualMemory = reinterpret_cast<prototypes::fpNtReadVirtualMemory>(executableMemory);

    NTSTATUS result = NtReadVirtualMemory(processHandle, baseAddress, buffer, size, (LPDWORD)&bytesRead);
    VirtualFree(executableMemory, sizeof(opcodes), MEM_RELEASE);
    return result;
}


char* MemoryUtils::ScanEx(const char* pattern, char* begin, const size_t size, const HANDLE processHandle)
{
    if (!pattern || !size)
        return nullptr;

    const size_t patternLength = strlen(pattern);

    for (char* curr = begin; curr < begin + size; )
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQueryEx(processHandle, curr, &mbi, sizeof(mbi)))
            break;

        if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        {
            curr = reinterpret_cast<char*>(mbi.BaseAddress) + mbi.RegionSize;
            continue;
        }

        std::unique_ptr<char[]> buffer(new char[mbi.RegionSize]);
        size_t bytesRead = 0;

        if (!NT_SUCCESS(NtReadVirtualMemory(processHandle, mbi.BaseAddress, buffer.get(), mbi.RegionSize, &bytesRead)) || bytesRead == 0)
        {
            curr = reinterpret_cast<char*>(mbi.BaseAddress) + mbi.RegionSize;
            continue;
        }

        std::byte* result = memmem(reinterpret_cast<std::byte*>(buffer.get()), bytesRead, reinterpret_cast<const std::byte*>(pattern), patternLength);

        if (result)
            return curr + (result - reinterpret_cast<std::byte*>(buffer.get()));

        curr = reinterpret_cast<char*>(mbi.BaseAddress) + mbi.RegionSize;
    }

    return nullptr;
}
