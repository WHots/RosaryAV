#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <vector>
#include <cstdint>
#include <memory>
#include <optional>

#include "prototypes.hpp"
#include <string>






class MemoryUtils
{

    struct MemoryProtectionInfo
    {
        void* BaseAddress;
        size_t Size;
        DWORD Protect;
        DWORD State;
    };


    /// <summary>
    /// Reads virtual memory from a specified process into a buffer.
    /// </summary>
    /// <typeparam name="T">The type of data to be read.</typeparam>
    /// <param name="processHandle">A handle to the process from which to read memory.</param>
    /// <param name="baseAddress">The base address in the specified process from which to read.</param>
    /// <param name="buffer">The buffer into which the contents from the address space of the specified process will be copied.</param>
    /// <param name="size">The number of bytes to be read from the specified process.</param>
    /// <param name="bytesRead">A pointer to a variable that receives the number of bytes transferred into the specified buffer.</param>
    /// <returns>Returns an NTSTATUS code indicating the result of the read operation.</returns>
    template<typename T>
    NTSTATUS ReadVirtualMemory(const HANDLE processHandle, const PVOID baseAddress, const PVOID buffer, const size_t size, size_t* bytesRead) const
    {
        return NtReadVirtualMemory(processHandle, baseAddress, buffer, size, bytesRead);
    }   

    /// <summary>
    /// Retrieves the DOS header of an image based on its base address.
    /// </summary>
    /// <param name="imageBase">The base address of the image whose DOS header is to be retrieved.</param>
    /// <returns>An optional containing the IMAGE_DOS_HEADER pointer if successful, std::nullopt otherwise.</returns>
    std::optional<IMAGE_DOS_HEADER*> GetDosHeader(uintptr_t imageBase);

    /// <summary>
    /// Retrieves the NT headers of an image based on its base address.
    /// </summary>
    /// <param name="imageBase">The base address of the image whose NT headers are to be retrieved.</param>
    /// <returns>An optional containing the IMAGE_NT_HEADERS pointer if successful, std::nullopt otherwise.</returns>
    std::optional<IMAGE_NT_HEADERS*> GetNtHeaders(uintptr_t imageBase);  

    /// <summary>
    /// Scans the memory of a target process for a specific pattern.
    /// </summary>
    /// <param name="pattern">The pattern to search for.</param>
    /// <param name="moduleName">The name of the module within the target process to search.</param>
    /// <param name="size">The size of the memory region to search, in bytes.</param>
    /// <param name="hProcess">The handle to the target process.</param>
    /// <returns>The address where the pattern was found, or nullptr if the pattern was not found.</returns>
    char* ScanEx(const char* pattern, const std::wstring& moduleName, const size_t size, const HANDLE hProcess);


private:


    /// <summary>
    /// Searches for a sequence of bytes (needle) within a block of memory (haystack).
    /// </summary>
    /// <param name="haystack">The block of memory to search within.</param>
    /// <param name="haystack_len">The size of the haystack in bytes.</param>
    /// <param name="needle">The sequence of bytes to search for.</param>
    /// <param name="needle_len">The length of the needle in bytes.</param>
    /// <returns>A pointer to the beginning of the needle in the haystack, or nullptr if the needle is not found.</returns>
    inline std::byte* memmem(std::byte* haystack, size_t haystack_len, const void* needle, size_t needle_len);

    /// <summary>
    /// Reads data from the virtual memory of a process.
    /// </summary>
    /// <param name="processHandle">A handle to the process to read from.</param>
    /// <param name="baseAddress">The base address of the memory to read.</param>
    /// <param name="buffer">A buffer to store the read data.</param>
    /// <param name="size">The size of the data to read in bytes.</param>
    /// <param name="bytesRead">A pointer to a variable that will receive the number of bytes read.</param>
    /// <returns>The NTSTATUS result of the read operation.</returns>
    inline NTSTATUS NtReadVirtualMemory(const HANDLE processHandle, const PVOID baseAddress, const PVOID buffer, const size_t size, size_t* bytesRead) const;

    /// <summary>
    /// Calculates the relative virtual address (RVA) based on a given base address and RVA offset.
    /// </summary>
    /// <param name="base">The base address from which the RVA is calculated.</param>
    /// <param name="rva">The relative virtual address offset to be added to the base address.</param>
    /// <returns>The calculated RVA as an uintptr_t value.</returns>
    inline uintptr_t CalculateRva(uintptr_t base, DWORD rva);

    /// <summary>
    /// Checks if a 64-bit memory address is canonical.
    /// </summary>
    /// <param name="address">The 64-bit memory address to check.</param>
    /// <returns>True if the address is canonical, false otherwise.</returns>
    inline bool IsCanonical(uint64_t address);

    /// <summary>
    /// Retrieves the base address of a module within the specified process.
    /// </summary>
    /// <param name="hProcess">The handle to the target process.</param>
    /// <param name="moduleName">The name of the module to retrieve the base address for.</param>
    /// <returns>The base address of the specified module, or nullptr if the module could not be found.</returns>
    inline char* GetModuleBaseAddressEx(const HANDLE hProcess, const std::wstring& moduleName);
};