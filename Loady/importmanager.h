#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <stdexcept>


#include "memutils.h"


struct ImportUtils 
{

    explicit ImportUtils(HMODULE moduleHandle);
    ~ImportUtils();


    ImportUtils(const ImportUtils&) = delete;
    ImportUtils& operator=(const ImportUtils&) = delete;
    ImportUtils(ImportUtils&&) = delete;
    ImportUtils& operator=(ImportUtils&&) = delete;


    /// <summary>
    /// Dynamically imports a function from a specified module, providing options to use either the standard GetProcAddress, 
    /// a custom method, or GetExportAddress for address retrieval.
    /// </summary>
    /// <typeparam name="T">The function pointer type to which the imported function will be cast.</typeparam>
    /// <param name="module">The name of the module from which to import the function.</param>
    /// <param name="method">The name of the function to import.</param>
    /// <param name="apiLocation">Specifies the method of address retrieval: 1 for GetExportAddress, 0 for custom address retrieval 
    /// (using GetProcedureAddressA) Defaults to 1.</param>
    /// <returns>A function pointer of type T to the imported function, or nullptr if the function cannot be imported.</returns>   
    template <typename T>
    T DynamicImporter(const char* method, int apiLocation = 1)
    {
        switch (apiLocation) 
        {
            case 0:
                return reinterpret_cast<T>(GetProcedureAddressA(hModule, method));           
            case 1:
                return reinterpret_cast<T>(GetExportAddress(hModule, method, TRUE));
            default:
                return nullptr;
        }
    }
    

private:

    HMODULE hModule;

    /// <summary>
    /// Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL).
    /// </summary>
    /// <param name="moduleHandle">A handle to the DLL module that contains the function or variable.</param>
    /// <param name="method">The name of the function or variable.</param>
    /// <returns>A pointer to the exported function or variable, or nullptr if the function fails.</returns>
    FARPROC GetProcedureAddressA(HMODULE moduleHandle, const char* method) const;
    /// <summary>
    /// Internal helper function to retrieve data directory entries from an image file based on the specified directory entry.
    /// </summary>
    /// <param name="Base">Base address of the image or mapped file.</param>
    /// <param name="MappedAsImage">Boolean value indicating whether the file is mapped as an image.</param>
    /// <param name="Size">Pointer to a variable that receives the size of the data directory.</param>
    /// <param name="SizeOfHeaders">Size of the headers in the image file.</param>
    /// <param name="DataDirectory">Pointer to the image data directory.</param>
    /// <param name="ImageFileHeader">Pointer to the image file header.</param>
    /// <param name="ImageOptionalHeader">Pointer to the image optional header.</param>
    /// <returns>Pointer to the data directory entry if found; otherwise, nullptr.</returns>
    inline PVOID __stdcall ImageDirectoryEntryToDataInternal(PVOID Base, BOOLEAN MappedAsImage, ULONG* Size, DWORD SizeOfHeaders, IMAGE_DATA_DIRECTORY* DataDirectory, IMAGE_FILE_HEADER* ImageFileHeader, void* ImageOptionalHeader) const;
    /// <summary>
    /// Retrieves a specific directory entry from a 32-bit image file.
    /// </summary>
    /// <param name="Base">Base address of the image or mapped file.</param>
    /// <param name="MappedAsImage">Boolean value indicating whether the file is mapped as an image.</param>
    /// <param name="DirectoryEntry">The directory entry to be retrieved.</param>
    /// <param name="Size">Pointer to a variable that receives the size of the directory entry.</param>
    /// <param name="ImageFileHeader">Pointer to the image file header.</param>
    /// <param name="ImageOptionalHeader">Pointer to the image optional header.</param>
    /// <returns>Pointer to the directory entry if found; otherwise, nullptr.</returns>
    PVOID __stdcall ImageDirectoryEntryToData32(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, ULONG* Size, IMAGE_FILE_HEADER* ImageFileHeader, IMAGE_OPTIONAL_HEADER32* ImageOptionalHeader) const;
    /// <summary>
    /// Retrieves a specific directory entry from a 64-bit image file.
    /// </summary>
    /// <param name="Base">Base address of the image or mapped file.</param>
    /// <param name="MappedAsImage">Boolean value indicating whether the file is mapped as an image.</param>
    /// <param name="DirectoryEntry">The directory entry to be retrieved.</param>
    /// <param name="Size">Pointer to a variable that receives the size of the directory entry.</param>
    /// <param name="ImageFileHeader">Pointer to the image file header.</param>
    /// <param name="ImageOptionalHeader">Pointer to the image optional header.</param>
    /// <returns>Pointer to the directory entry if found; otherwise, nullptr.</returns>
    inline PVOID __stdcall ImageDirectoryEntryToData64(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, ULONG* Size, IMAGE_FILE_HEADER* ImageFileHeader, IMAGE_OPTIONAL_HEADER64* ImageOptionalHeader) const;
    /// <summary>
    /// Retrieves a specific directory entry from a ROM image file.
    /// </summary>
    /// <param name="Base">Base address of the ROM image file.</param>
    /// <param name="HeaderMagic">Magic number of the ROM image header.</param>
    /// <param name="DirectoryEntry">The directory entry to be retrieved.</param>
    /// <param name="Size">Pointer to a variable that receives the size of the directory entry.</param>
    /// <param name="ImageFileHeader">Pointer to the image file header.</param>
    /// <param name="ImageRomHeaders">Pointer to the ROM image optional header.</param>
    /// <returns>Pointer to the directory entry if found; otherwise, nullptr.</returns>
    inline PVOID __stdcall ImageDirectoryEntryToDataRom(PVOID Base, WORD HeaderMagic, USHORT DirectoryEntry, ULONG* Size, IMAGE_FILE_HEADER* ImageFileHeader, IMAGE_ROM_OPTIONAL_HEADER* ImageRomHeaders) const;
    /// <summary>
    /// Extended version of the function to retrieve a specific directory entry from an image file, providing support for different image formats.
    /// </summary>
    /// <param name="Base">Base address of the image or mapped file.</param>
    /// <param name="MappedAsImage">Boolean value indicating whether the file is mapped as an image.</param>
    /// <param name="DirectoryEntry">The directory entry to be retrieved.</param>
    /// <param name="Size">Pointer to a variable that receives the size of the directory entry.</param>
    /// <returns>Pointer to the directory entry if found; otherwise, nullptr.</returns>
    inline PVOID __stdcall ImageDirectoryEntryToDataEx(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, ULONG* Size) const;
    /// <summary>
    /// Maps a relative virtual address (RVA) to a specific section header in an image file.
    /// </summary>
    /// <param name="NtHeaders">Pointer to the NT headers of the image file.</param>
    /// <param name="Base">Base address of the image or mapped file.</param>
    /// <param name="Rva">The relative virtual address to be mapped.</param>
    /// <returns>Pointer to the corresponding section header, or nullptr if the section is not found.</returns>
    inline IMAGE_SECTION_HEADER* __stdcall ImageRvaToSection(PIMAGE_NT_HEADERS NtHeaders, PVOID Base, ULONG Rva) const;
    /// <summary>
    /// Converts a relative virtual address (RVA) in an image to a virtual address (VA).
    /// </summary>
    /// <param name="NtHeaders">Pointer to the NT headers of the image file.</param>
    /// <param name="Base">Base address of the image or mapped file.</param>
    /// <param name="Rva">The relative virtual address to be converted.</param>
    /// <returns>The corresponding virtual address, or nullptr if the conversion fails.</returns>
    inline PVOID __stdcall ImageRvaToVa(PIMAGE_NT_HEADERS NtHeaders, void* Base, DWORD Rva) const;
    /// <summary>
    /// Retrieves the address of an exported function from the specified module, providing support for different image formats and mapping scenarios.
    /// </summary>
    /// <param name="hModule">A handle to the module that contains the function.</param>
    /// <param name="lpProcName">The name or ordinal of the function.</param>
    /// <param name="MappedAsImage">Boolean value indicating whether the module is mapped as an image.</param>
    /// <returns>A pointer to the exported function, or nullptr if the function cannot be found.</returns>
    FARPROC GetExportAddress(HMODULE hModule, LPCSTR lpProcName, BOOLEAN MappedAsImage) const;
};