#include "memutils.h"





namespace memoryutils
{
   
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

        for (const char* h = (const char*)haystack; haystack_len >= needle_len; ++h, --haystack_len, ++offset) 
        {
            if (!memcmp(h, needle, needle_len))            
                return (void*)h;          
        }

        return NULL;
    }


    char* ScanEx(const char* pattern, char* begin, intptr_t size, HANDLE hProc)
    {

        char* match = nullptr;
        SIZE_T bytesRead;
        DWORD oldProtect;
        std::vector<char> buffer{};
        MEMORY_BASIC_INFORMATION mbi{};
        mbi.RegionSize = 0x1000;

        VirtualQueryEx(hProc, (LPCVOID)begin, &mbi, sizeof(mbi));

        const size_t patternLength = strlen(pattern);

        for (char* curr = begin; curr < begin + size; curr += mbi.RegionSize)
        {
            if (!VirtualQueryEx(hProc, curr, &mbi, sizeof(mbi)))
                continue;

            if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS)
                continue;

            buffer.resize(mbi.RegionSize);

            if (VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                if (NT_SUCCESS(NtReadVirtualMemory(hProc, mbi.BaseAddress, buffer.data(), mbi.RegionSize, (LPDWORD)&bytesRead)))
                {
                    VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, oldProtect, &oldProtect);

                    void* result = memmem(buffer.data(), bytesRead, pattern, patternLength);
                    if (result != nullptr)
                    {
                        match = curr + ((char*)result - buffer.data());
                        break;
                    }
                }
            }
        }

        return match;
    }

}