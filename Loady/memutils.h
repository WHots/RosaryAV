#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <vector>
#include <cstdint>
#include <memory>
#include "prototypes.hpp"






class MemoryUtils 
{

    template<typename T>
    NTSTATUS ReadVirtualMemory(HANDLE processHandle, PVOID baseAddress, T* buffer, size_t size, size_t* bytesRead) const 
    {
        return NtReadVirtualMemory(processHandle, baseAddress, buffer, size, bytesRead);
    }


    /// <summary>
    /// Scans a process's memory for a specific pattern.
    /// </summary>
    /// <param name="pattern">The pattern to search for.</param>
    /// <param name="begin">The starting address of the memory region to scan.</param>
    /// <param name="size">The size of the memory region to scan in bytes.</param>
    /// <param name="processHandle">A handle to the process to scan.</param>
    /// <returns>The address of the first occurrence of the pattern, or nullptr if not found.</returns>
    char* ScanEx(const char* pattern, char* begin, size_t size, HANDLE processHandle) const;
    

private:


    /// <summary>
    /// Performs a memory search for a needle within a haystack.
    /// </summary>
    /// <param name="haystack">The memory region to search within.</param>
    /// <param name="haystack_len">The length of the haystack in bytes.</param>
    /// <param name="needle">The pattern to search for.</param>
    /// <param name="needle_len">The length of the needle in bytes.</param>
    /// <returns>A pointer to the first occurrence of the needle within the haystack, or nullptr if not found.</returns>
    inline void* memmem(const void* haystack, size_t haystack_len, const void* const needle, const size_t needle_len);
    /// <summary>
    /// Reads data from the virtual memory of a process.
    /// </summary>
    /// <param name="processHandle">A handle to the process to read from.</param>
    /// <param name="baseAddress">The base address of the memory to read.</param>
    /// <param name="buffer">A buffer to store the read data.</param>
    /// <param name="size">The size of the data to read in bytes.</param>
    /// <param name="bytesRead">A pointer to a variable that will receive the number of bytes read.</param>
    /// <returns>The NTSTATUS result of the read operation.</returns>
    inline NTSTATUS NtReadVirtualMemory(HANDLE processHandle, PVOID baseAddress, PVOID buffer, size_t size, size_t* bytesRead) const;
};