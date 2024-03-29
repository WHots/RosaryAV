#include "fileutils.h"






namespace fileutils
{

    BOOL GetExecutablePathName(const HANDLE hProcess, std::string& outPath)
    {

        wchar_t buffer[MAX_PATH];

        int result = K32GetModuleFileNameExW(hProcess, NULL, buffer, MAX_PATH);

        if (result != 0)
        {
            std::wstring wstr(buffer);
            outPath.assign(wstr.begin(), wstr.end());
        }

        return (result != 0);
    }


    int FilePatched(const wchar_t* filePath)
    {

        DWORD lpdwHandle;
        std::string internalName = "";

        DWORD size = GetFileVersionInfoSizeW(filePath, &lpdwHandle);
        std::vector<char> data(size);

        if (!GetFileVersionInfoW(filePath, 0, size, data.data()))
            return -1;

        VS_FIXEDFILEINFO* fileInfo{};
        UINT length;

        if (VerQueryValueW(data.data(), L"\\", (LPVOID*)&fileInfo, &length))
            return ((fileInfo->dwFileFlagsMask & VS_FF_PATCHED) && (fileInfo->dwFileFlags & VS_FF_PATCHED)) ? 1 : 0;


        return -1;
    }


    int IsFileTypeUnknown(const wchar_t* filePath)
    {

        DWORD lpdwHandle;

        DWORD size = GetFileVersionInfoSizeW(filePath, &lpdwHandle);
        std::vector<char> data(size);

        if (!GetFileVersionInfoW(filePath, 0, size, data.data()))
            return -1;

        VS_FIXEDFILEINFO* fileInfo{};
        UINT length;

        if (VerQueryValueW(data.data(), L"\\", (LPVOID*)&fileInfo, &length))
            return (fileInfo->dwFileType == VFT_UNKNOWN) ? 1 : 0;


        return -1;
    }


    std::string GetFileStemName(const std::string& filePath)
    {
        std::filesystem::path fsPath(filePath);
        return fsPath.stem().string();
    }


    std::string CalculateFileMD5(const std::string& fileName)
    {

        using namespace CryptoPP;

        MD5 hash;
        std::string digest;

        FileSource file(fileName.c_str(), true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));

        return digest;
    }


    std::string GetFileInternalName(const wchar_t* filePath)
    {

        DWORD lpdwHandle;
        std::string internalName = "";

        DWORD size = GetFileVersionInfoSizeW(filePath, &lpdwHandle);

        std::vector<char> data(size);

        if (!GetFileVersionInfoW(filePath, 0, size, data.data()))
            return internalName;

        void* buffer{};
        UINT length = 0;

        if (VerQueryValueW(data.data(), TEXT("\\StringFileInfo\\040904b0\\InternalName"), &buffer, &length))
            internalName = stringutil::WideStringToUTF8(static_cast<wchar_t*>(buffer));

        return internalName;
    }


    LPTSTR GetFileOwnerSid(const wchar_t* filePath)
    {

        ImportUtils utils(GetModuleHandleW(L"advapi32.dll"));

        auto GetNamedSecurityInfoW = utils.DynamicImporter<prototypes::fpGetNamedSecurityInfoW>("GetNamedSecurityInfoW");

        if (!GetNamedSecurityInfoW)
            return nullptr;


        PSECURITY_DESCRIPTOR pSD = nullptr;
        PSID ownerSID = nullptr;
        DWORD res = GetNamedSecurityInfoW(filePath, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &ownerSID, nullptr, nullptr, nullptr, &pSD);

        std::unique_ptr<void, decltype(&LocalFree)> sdGuard(pSD, LocalFree);


        if (res != ERROR_SUCCESS)
            return nullptr;

        if (!IsValidSid(ownerSID))
            return nullptr;


        LPTSTR sidString = nullptr;
       
        auto ConvertSidToStringSidW = utils.DynamicImporter<prototypes::fpConvertSidToStringSidW>("ConvertSidToStringSidW");

        if (!ConvertSidToStringSidW || !ConvertSidToStringSidW(ownerSID, &sidString))
            return nullptr;

        std::unique_ptr<TCHAR, decltype(&LocalFree)> sidGuard(sidString, LocalFree);

        return _tcsdup(sidString);
    }


    double GetFileEntropy(const std::string& filePath)
    {

        std::ifstream file(filePath, std::ios::binary);

        if (!file)
            return 0.0;


        std::array<long, 256> frequency{};
        std::vector<char> buffer{};

        std::istreambuf_iterator<char> fileIterator(file);
        std::istreambuf_iterator<char> eos;

        buffer.assign(fileIterator, eos);

        std::for_each(buffer.begin(), buffer.end(), [&frequency](char c) 
        {
            ++frequency[static_cast<unsigned char>(c)];
        });

        double entropy = 0.0;

        std::for_each(frequency.begin(), frequency.end(), [&entropy, totalBytes = buffer.size()](long freq) 
        {
            if (freq > 0) 
            {
                double packedProbability = static_cast<double>(freq) / totalBytes;
                entropy -= packedProbability * std::log2(packedProbability);
            }
        });
        
        return entropy;
    }

}