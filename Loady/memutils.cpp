#include "memutils.h"




inline void* MemoryUtils::memmem(const void* haystack, size_t haystack_len, const void* const needle, const size_t needle_len)
{

    if (haystack == NULL) return NULL;
    if (haystack_len == 0) return NULL;
    if (needle == NULL) return NULL;
    if (needle_len == 0) return NULL;

    DWORDLONG offset = 0;

    for (const char* h = (const char*)haystack; haystack_len >= needle_len; ++h, --haystack_len, ++offset)
    {
        if (!memcmp(h, needle, needle_len))
            return (void*)h;
    }

    return NULL;
}


inline NTSTATUS MemoryUtils::NtReadVirtualMemory(HANDLE processHandle, PVOID baseAddress, PVOID buffer, size_t size, size_t* bytesRead) const
{

    static const unsigned char opcodes[] =
    {
      0x4c, 0x8b, 0xd1, 0xb8, 0x3f, 0x00, 0x00, 0x00,
      0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe, 0x7f, 0x01,
      0x75, 0x03, 0x0f, 0x05, 0xc3
    };

    void* executableMemory = VirtualAlloc(0, sizeof(opcodes), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(executableMemory, opcodes, sizeof(opcodes));

    auto NtReadVirtualMemory = reinterpret_cast<prototypes::fpNtReadVirtualMemory>(executableMemory);

    NTSTATUS result = NtReadVirtualMemory(processHandle, baseAddress, buffer, size, (LPDWORD)&bytesRead);
    VirtualFree(executableMemory, sizeof(opcodes), MEM_RELEASE);
    return result;
}


char* MemoryUtils::ScanEx(const char* pattern, char* begin, size_t size, HANDLE processHandle) const
{

    if (!pattern || !size)
        return nullptr;

    const size_t patternLength = strlen(pattern);

    for (char* curr = begin; curr < begin + size; )
    {

        MEMORY_BASIC_INFORMATION mbi{};

        if (!VirtualQueryEx(processHandle, curr, &mbi, sizeof(mbi)))
            break;

        if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS)
        {
            curr += mbi.RegionSize;
            continue;
        }

        std::unique_ptr<char[]> buffer(new char[mbi.RegionSize]);
        SIZE_T bytesRead;

        if (!NT_SUCCESS(NtReadVirtualMemory(processHandle, mbi.BaseAddress, buffer.get(), mbi.RegionSize, &bytesRead)))
            break;

        void* result = nullptr;

        for (const char* h = buffer.get(); h + patternLength <= buffer.get() + bytesRead; ++h) 
        {
            if (!memcmp(h, pattern, patternLength)) 
            {
                result = (void*)h;
                break;
            }
        }

        if (result)
            return curr + ((char*)result - buffer.get());


        curr += mbi.RegionSize;
    }

    return nullptr;
}
