#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <vector>
#include "prototypes.hpp"






namespace memoryutils
{   
    /// <summary>
    /// Reads process memory via NtReadVirtualMemory for a specific byte string / pattern.
    /// </summary>
    /// <param name="ProcessHandle">Handle to the target process.</param>
    /// <param name="BaseAddress">Base address of the memory to read from.</param>
    /// <param name="Buffer">Pointer to the buffer where the read data will be stored.</param>
    /// <param name="NumberOfBytesToRead">Number of bytes to read from the target process.</param>
    /// <param name="NumberOfBytesReaded">Pointer to store the number of bytes actually read.</param>
    /// <returns>NTSTATUS indicating the result of the memory read operation.</returns>
    inline NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
    /// <summary>
    /// Searches for a subsequence in a given memory block.
    /// </summary>
    /// <param name="haystack">Pointer to the memory block to search in.</param>
    /// <param name="haystack_len">Length of the memory block.</param>
    /// <param name="needle">Pointer to the subsequence to search for.</param>
    /// <param name="needle_len">Length of the subsequence to search for.</param>
    /// <returns>A pointer to the first occurrence of the subsequence if found, otherwise nullptr.</returns>
    inline void* memmem(const void* haystack, size_t haystack_len, const void* const needle, const size_t needle_len);
    /// <summary>
    /// Reads process memory via NtReadVirtualMemory for a specific byte string / pattern.
    /// </summary>
    /// <param name="pied">Target process ID.</param>
    /// <param name="mod_name">Module name to read.</param>
    /// <param name="pattern">Pattern, typically an IDA or Ghidra pattern is acceptable.</param>
    char* ScanEx(const char* pattern, char* begin, intptr_t size, HANDLE hProc);

}