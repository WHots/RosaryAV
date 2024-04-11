#include "memutils.h"





inline uintptr_t MemoryUtils::CalculateRva(uintptr_t base, DWORD rva)
{
    return base + rva;
}


inline bool MemoryUtils::IsCanonical(uint64_t address)
{
    uint16_t upperBits = address >> 48;
    return upperBits == 0x0000 || upperBits == 0xFFFF;
}


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
        0x4c, 0x8b, 0xd1, 0xb8, 0x3f, 0x00, 0x00, 0x00, 0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe, 0x7f, 0x01, 0x75, 0x03, 0x0f, 0x05, 0xc3
    };

    void* executableMemory = malloc(sizeof(opcodes));

    if (executableMemory)
        memcpy(executableMemory, opcodes, sizeof(opcodes));
    else
        return 0;

    auto NtReadVirtualMemory = reinterpret_cast<prototypes::fpNtReadVirtualMemory>(executableMemory);

    NTSTATUS result = NtReadVirtualMemory(processHandle, baseAddress, buffer, size, (LPDWORD)bytesRead);
    free(executableMemory);

    return result;
}


inline char* MemoryUtils::GetModuleBaseAddressEx(const HANDLE hProcess, const std::wstring& moduleName) 
{

    HMODULE moduleHandle = nullptr;
    DWORD bytesReturned = 0;

    if (!K32EnumProcessModulesEx(hProcess, &moduleHandle, sizeof(moduleHandle), &bytesReturned, LIST_MODULES_ALL))
        return nullptr;

    wchar_t buffer[MAX_PATH] = {};

    if (!GetModuleFileNameExW(hProcess, moduleHandle, buffer, MAX_PATH))
        return nullptr;

    if (std::wstring(buffer).find(moduleName) == std::wstring::npos)
        return nullptr;

    if (!moduleHandle)
        return nullptr;

    return reinterpret_cast<char*>(moduleHandle);
}


char* MemoryUtils::ScanEx(const char* pattern, const std::wstring& moduleName, const size_t size, const HANDLE hProcess)
{

    if (!pattern || !size) 
        return nullptr;

    auto begin = GetModuleBaseAddressEx(hProcess, moduleName);

    if (!begin)
        return nullptr;


    const size_t patternLength = strlen(pattern);

    for (char* curr = begin; curr < begin + size;) 
    {
        MEMORY_BASIC_INFORMATION mbi{};

        if (!VirtualQueryEx(hProcess, curr, &mbi, sizeof(mbi)))
            break;

        if (!(mbi.Protect & PAGE_READONLY) && !(mbi.Protect & PAGE_EXECUTE_READ) && !(mbi.Protect & PAGE_EXECUTE_READWRITE) && !(mbi.Protect & PAGE_READWRITE)) 
        {
            DWORD oldProtect;

            if (!VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, PAGE_READONLY, &oldProtect))
            {
                curr = reinterpret_cast<char*>(mbi.BaseAddress) + mbi.RegionSize;
                continue;
            }       
        }

        std::unique_ptr<char[]> buffer(new char[mbi.RegionSize]);
        size_t bytesRead = 0;

        if (!NT_SUCCESS(NtReadVirtualMemory(hProcess, mbi.BaseAddress, buffer.get(), mbi.RegionSize, &bytesRead)) || bytesRead == 0) 
        {
            curr = reinterpret_cast<char*>(mbi.BaseAddress) + mbi.RegionSize;
            continue;
        }

        std::byte* result = memmem(reinterpret_cast<std::byte*>(buffer.get()), bytesRead, reinterpret_cast<const std::byte*>(pattern), patternLength);

        if (result) 
        {
            DWORD oldProtect;
            VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &oldProtect);

            return curr + (result - reinterpret_cast<std::byte*>(buffer.get()));
        }

        DWORD oldProtect;
        VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &oldProtect);

        curr = reinterpret_cast<char*>(mbi.BaseAddress) + mbi.RegionSize;
    }

    return nullptr;
}


std::optional<IMAGE_DOS_HEADER*> MemoryUtils::GetDosHeader(uintptr_t imageBase)
{
    IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(imageBase);

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) 
        return std::nullopt;
    
    return dosHeader;
}


std::optional<IMAGE_NT_HEADERS64*> MemoryUtils::GetNtHeaders(uintptr_t imageBase)
{
    if (auto dosHeader = GetDosHeader(imageBase)) 
    {
        IMAGE_NT_HEADERS64* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(imageBase + (*dosHeader)->e_lfanew);

        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
            return std::nullopt;
      
        return ntHeaders;
    }

    return std::nullopt;
}