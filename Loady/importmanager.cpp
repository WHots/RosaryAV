#include "importmanager.h"







ImportUtils::ImportUtils(HMODULE moduleHandle) : hModule(moduleHandle) 
{
    if (!hModule)
        throw std::invalid_argument("Invalid module handle");
}


FARPROC ImportUtils::GetProcedureAddressA(HMODULE moduleHandle, const char* method) const
{

    if (!moduleHandle || !method)
        return nullptr;


    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleHandle;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)moduleHandle + dosHeader->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)moduleHandle + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    if (importDescriptor != NULL)
    {
        while (importDescriptor->Name != 0)
        {
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)moduleHandle + importDescriptor->OriginalFirstThunk);

            while (thunk && thunk->u1.Function)
            {
                if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
                {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)moduleHandle + thunk->u1.AddressOfData);

                    if (strcmp(method, (char*)importByName->Name) == 0)
                    {
                        DWORD_PTR functionRVA = ntHeaders->OptionalHeader.ImageBase + (DWORD_PTR)thunk->u1.Function;
                        return (FARPROC)functionRVA;
                    }
                }
                thunk++;
            }
            importDescriptor++;
        }
    }

    return nullptr;
}


PVOID __stdcall ImportUtils::ImageDirectoryEntryToDataInternal(PVOID Base, BOOLEAN MappedAsImage, ULONG* Size, DWORD SizeOfHeaders, IMAGE_DATA_DIRECTORY* DataDirectory, IMAGE_FILE_HEADER* ImageFileHeader, void* ImageOptionalHeader) const
{

    if (Base == nullptr || Size == nullptr || DataDirectory == nullptr || ImageFileHeader == nullptr || ImageOptionalHeader == nullptr)
        return nullptr;


    *Size = 0;

    if (DataDirectory->VirtualAddress == 0 || DataDirectory->Size == 0 || SizeOfHeaders == 0)
        return nullptr;

    *Size = DataDirectory->Size;

    if (MappedAsImage || DataDirectory->VirtualAddress < SizeOfHeaders) 
        return (char*)Base + DataDirectory->VirtualAddress;

    const WORD SizeOfOptionalHeader = ImageFileHeader->SizeOfOptionalHeader;
    const WORD NumberOfSections = ImageFileHeader->NumberOfSections;

    if (NumberOfSections == 0 || SizeOfOptionalHeader == 0) 
        return nullptr;
    

    const IMAGE_SECTION_HEADER* pSectionHeaders = reinterpret_cast<const IMAGE_SECTION_HEADER*>(reinterpret_cast<const BYTE*>(ImageOptionalHeader) + SizeOfOptionalHeader);

    for (DWORD i = 0; i < NumberOfSections; ++i) 
    {
        const IMAGE_SECTION_HEADER* pSectionHeader = &pSectionHeaders[i];

        if (DataDirectory->VirtualAddress >= pSectionHeader->VirtualAddress && DataDirectory->VirtualAddress < pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData) 
            return (char*)Base + (DataDirectory->VirtualAddress - pSectionHeader->VirtualAddress) + pSectionHeader->PointerToRawData;      
    }

    return nullptr;
}


PVOID __stdcall ImportUtils::ImageDirectoryEntryToData32(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, ULONG* Size, IMAGE_FILE_HEADER* ImageFileHeader, IMAGE_OPTIONAL_HEADER32* ImageOptionalHeader) const
{

    *Size = 0;

    if (DirectoryEntry >= ImageOptionalHeader->NumberOfRvaAndSizes)
        return nullptr;

    IMAGE_DATA_DIRECTORY* DataDirectory = &ImageOptionalHeader->DataDirectory[DirectoryEntry];

    return (!DataDirectory->VirtualAddress || !DataDirectory->Size) ? nullptr : ImageDirectoryEntryToDataInternal(Base, MappedAsImage, Size, ImageOptionalHeader->SizeOfHeaders, DataDirectory, ImageFileHeader, ImageOptionalHeader);
}


PVOID __stdcall ImportUtils::ImageDirectoryEntryToData64(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, ULONG* Size, IMAGE_FILE_HEADER* ImageFileHeader, IMAGE_OPTIONAL_HEADER64* ImageOptionalHeader) const
{

    *Size = 0;

    if (DirectoryEntry >= ImageOptionalHeader->NumberOfRvaAndSizes)
        return nullptr;

    IMAGE_DATA_DIRECTORY* DataDirectory = &ImageOptionalHeader->DataDirectory[DirectoryEntry];

    return (!DataDirectory->VirtualAddress || !DataDirectory->Size) ? nullptr : ImageDirectoryEntryToDataInternal(Base, MappedAsImage, Size, ImageOptionalHeader->SizeOfHeaders, DataDirectory, ImageFileHeader, ImageOptionalHeader);
}


PVOID __stdcall ImportUtils::ImageDirectoryEntryToDataRom(PVOID Base, WORD HeaderMagic, USHORT DirectoryEntry, ULONG* Size, IMAGE_FILE_HEADER* ImageFileHeader, IMAGE_ROM_OPTIONAL_HEADER* ImageRomHeaders) const
{

    *Size = 0;

    if (ImageFileHeader->NumberOfSections <= 0u || !ImageFileHeader->SizeOfOptionalHeader)
        return nullptr;

    const IMAGE_SECTION_HEADER* pSectionHeader = reinterpret_cast<const IMAGE_SECTION_HEADER*>(reinterpret_cast<const BYTE*>(ImageRomHeaders) + ImageFileHeader->SizeOfOptionalHeader);

    WORD j = 0;

    for (; j < ImageFileHeader->NumberOfSections; ++j, ++pSectionHeader) 
    {
        if (DirectoryEntry == 3 && _stricmp(reinterpret_cast<const char*>(pSectionHeader->Name), ".pdata") == 0)
            break;

        if (DirectoryEntry == 6 && _stricmp(reinterpret_cast<const char*>(pSectionHeader->Name), ".rdata") == 0) 
        {
            *Size = 0;

            for (const BYTE* i = reinterpret_cast<const BYTE*>(Base) + pSectionHeader->PointerToRawData + 0xC; *reinterpret_cast<const DWORD*>(i); i += 0x1C)
                *Size += 0x1C;
            
            break;
        }
    }

    if (j >= ImageFileHeader->NumberOfSections) 
        return nullptr;

    return (char*)Base + pSectionHeader->PointerToRawData;
}


PVOID __stdcall ImportUtils::ImageDirectoryEntryToDataEx(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, ULONG* Size) const
{

    if (Size == nullptr || Base == nullptr)
        return nullptr;


    *Size = 0;

    auto pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(Base);

    LONG NtHeaderFileOffset = pDosHeader->e_lfanew;
    auto ImageNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<LPBYTE>(Base) + NtHeaderFileOffset);

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || NtHeaderFileOffset <= 0 || NtHeaderFileOffset >= 0x10000000u || ImageNtHeader->Signature != IMAGE_NT_SIGNATURE)   
        return nullptr;

    auto ImageFileHeader = &ImageNtHeader->FileHeader;
    auto ImageOptionalHeader = &ImageNtHeader->OptionalHeader;


    switch (ImageOptionalHeader->Magic)
    {
        case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            return ImageDirectoryEntryToData32(Base, MappedAsImage, DirectoryEntry, Size, ImageFileHeader, reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(ImageOptionalHeader));
        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            return ImageDirectoryEntryToData64(Base, MappedAsImage, DirectoryEntry, Size, ImageFileHeader, reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(ImageOptionalHeader));
        case IMAGE_ROM_OPTIONAL_HDR_MAGIC:
            return ImageDirectoryEntryToDataRom(Base, IMAGE_ROM_OPTIONAL_HDR_MAGIC, DirectoryEntry, Size, ImageFileHeader, reinterpret_cast<IMAGE_ROM_OPTIONAL_HEADER*>(ImageOptionalHeader));
    }

    return nullptr;
}



IMAGE_SECTION_HEADER* __stdcall ImportUtils::ImageRvaToSection(PIMAGE_NT_HEADERS NtHeaders, PVOID Base, ULONG Rva) const
{

    if (NtHeaders == nullptr)
        return nullptr;


    DWORD dwNumberOfSections = NtHeaders->FileHeader.NumberOfSections;

    if (!dwNumberOfSections)
        return nullptr;

    WORD SizeOfOptionalHeader = NtHeaders->FileHeader.SizeOfOptionalHeader;
    auto pSectionHeaders = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<BYTE*>(&NtHeaders->OptionalHeader) + SizeOfOptionalHeader);

    for (DWORD i = 0; i < dwNumberOfSections; ++i)
    {
        DWORD VirtualAddress = pSectionHeaders[i].VirtualAddress;
        DWORD SizeOfRawData = pSectionHeaders[i].SizeOfRawData;

        if (Rva >= VirtualAddress && Rva < VirtualAddress + SizeOfRawData)
            return &pSectionHeaders[i];
    }

    return nullptr;
}



PVOID __stdcall ImportUtils::ImageRvaToVa(PIMAGE_NT_HEADERS NtHeaders, void* Base, DWORD Rva) const
{
    IMAGE_SECTION_HEADER* ResultSection = nullptr;

    ResultSection = ImageRvaToSection(NtHeaders, static_cast<PVOID>(Base), Rva);

    if (!ResultSection)
        return nullptr;

    return (char*)Base + (Rva - ResultSection->VirtualAddress) + ResultSection->PointerToRawData;
}


FARPROC ImportUtils::GetExportAddress(HMODULE hModule, LPCSTR lpProcName, BOOLEAN MappedAsImage) const
{

    if (lpProcName == NULL)
        return nullptr;


    unsigned short ProcOrdinal = 0xFFFF;

    if ((ULONG_PTR)lpProcName < 0xFFFF) 
    {
        ProcOrdinal = (ULONG_PTR)lpProcName & 0xFFFF;
    }
    else 
    {
        if (lpProcName[0] == '#') 
        {
            DWORD OrdinalFromString = atoi(lpProcName + 1);

            if (OrdinalFromString < 0xFFFF && OrdinalFromString != 0) 
            {
                ProcOrdinal = OrdinalFromString & 0xFFFF;
                lpProcName = (LPCSTR)(ULONG_PTR)(ProcOrdinal);
            }
        }
    }

    IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)hModule;

    if (!DosHeader || DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;

    IMAGE_NT_HEADERS* NtHeader = (IMAGE_NT_HEADERS*)((DWORD_PTR)DosHeader + DosHeader->e_lfanew);

    if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;

    ULONG ExportDirectorySize = NULL;
    IMAGE_EXPORT_DIRECTORY* ExportDirectory = (IMAGE_EXPORT_DIRECTORY*)ImageDirectoryEntryToDataEx(DosHeader, MappedAsImage, IMAGE_DIRECTORY_ENTRY_EXPORT, &ExportDirectorySize);

    if (!ExportDirectory || !ExportDirectorySize)
        return nullptr;

    if (!ExportDirectory->NumberOfFunctions)
        return nullptr;

    if (ExportDirectorySize <= sizeof(IMAGE_EXPORT_DIRECTORY))     
        ExportDirectorySize = static_cast<DWORD>(ExportDirectory->AddressOfNameOrdinals - (DWORD)((BYTE*)(ExportDirectory)-(BYTE*)(DosHeader)) + max(ExportDirectory->NumberOfFunctions, ExportDirectory->NumberOfNames) * 255);


    DWORD AddressOfNamesRVA = ExportDirectory->AddressOfNames;
    DWORD AddressOfFunctionsRVA = ExportDirectory->AddressOfFunctions;
    DWORD AddressOfNameOrdinalsRVA = ExportDirectory->AddressOfNameOrdinals;

    DWORD* ExportNames = (DWORD*)(MappedAsImage ? ((BYTE*)DosHeader + AddressOfNamesRVA) : ImageRvaToVa(NtHeader, DosHeader, AddressOfNamesRVA));
    DWORD* Functions = (DWORD*)(MappedAsImage ? ((BYTE*)DosHeader + AddressOfFunctionsRVA) : ImageRvaToVa(NtHeader, DosHeader, AddressOfFunctionsRVA));
    WORD* Ordinals = (WORD*)(MappedAsImage ? ((BYTE*)DosHeader + AddressOfNameOrdinalsRVA) : ImageRvaToVa(NtHeader, DosHeader, AddressOfNameOrdinalsRVA));

    for (DWORD i = 0; i < ExportDirectory->NumberOfNames; i++) 
    {
        unsigned short OrdinalIndex = Ordinals[i];
        DWORD ExportFncOffset = Functions[OrdinalIndex];

        if (!ExportFncOffset)
            continue;

        char* ProcNamePtr = (char*)(MappedAsImage ? ((char*)DosHeader + ExportNames[i]) : ImageRvaToVa(NtHeader, DosHeader, ExportNames[i]));
        BYTE* ExportFnc = (BYTE*)(MappedAsImage ? ((BYTE*)DosHeader + ExportFncOffset) : ImageRvaToVa(NtHeader, DosHeader, ExportFncOffset));

        if (MappedAsImage && ExportFnc > (BYTE*)ExportDirectory && ExportFnc < (BYTE*)ExportDirectory + ExportDirectorySize) 
            continue;       


        if ((ULONG_PTR)lpProcName > 0xFFFF && strcmp(lpProcName, ProcNamePtr) == 0)
            return (FARPROC)ExportFnc;
        else if (OrdinalIndex + 1 == ProcOrdinal)
            return (FARPROC)ExportFnc;
    }

    return nullptr;
}


ImportUtils::~ImportUtils() = default;