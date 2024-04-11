#include "fileutils.h"






namespace fileutils
{

    BOOL GetExecutablePathName(const HANDLE hProcess, std::wstring& outPath)
    {
        wchar_t buffer[MAX_PATH];

        int result = K32GetModuleFileNameExW(hProcess, NULL, buffer, MAX_PATH);

        if (result != 0)
        {
            outPath.assign(buffer);
        }
        return (result != 0);
    }


    int FilePatched(const wchar_t* filePath)
    {

        DWORD lpdwHandle = 0;
        DWORD size = GetFileVersionInfoSizeW(filePath, &lpdwHandle);

        if (size == 0)     
            return -1;
        
        std::unique_ptr<char[]> dataPtr(new char[size]);
        char* data = dataPtr.get();

        if (!GetFileVersionInfoW(filePath, 0, size, data))      
            return -1;

        VS_FIXEDFILEINFO* fileInfo = nullptr;
        UINT length = 0;

        if (!VerQueryValueW(data, L"\\\\", reinterpret_cast<LPVOID*>(&fileInfo), &length) || fileInfo == nullptr)
            return -1;

        return ((fileInfo->dwFileFlagsMask & VS_FF_PATCHED) && (fileInfo->dwFileFlags & VS_FF_PATCHED)) ? 1 : 0;
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

        MD5 hash{};
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


    std::wstring GetFileOwnerSid(const std::wstring& filePath) 
    {

        ImportUtils utils(GetModuleHandleW(L"advapi32.dll"));
     
        auto GetNamedSecurityInfoW = utils.DynamicImporter<prototypes::fpGetNamedSecurityInfoW>("GetNamedSecurityInfoW");
        auto ConvertSidToStringSidW = utils.DynamicImporter<prototypes::fpConvertSidToStringSidW>("ConvertSidToStringSidW");

        if (!GetNamedSecurityInfoW || !ConvertSidToStringSidW)
            return std::wstring();


        PSECURITY_DESCRIPTOR pSD = nullptr;
        PSID ownerSID = nullptr;

        DWORD res = GetNamedSecurityInfoW(filePath.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &ownerSID, nullptr, nullptr, nullptr, &pSD);

        if (res != ERROR_SUCCESS)
            return std::wstring();

        std::unique_ptr<void, decltype(&LocalFree)> sdGuard(pSD, LocalFree);

        if (!IsValidSid(ownerSID)) 
            return std::wstring();       

        LPWSTR sidString = nullptr;

        if (!ConvertSidToStringSidW(ownerSID, &sidString))
            return std::wstring();

        std::wstring result(sidString);
        LocalFree(sidString);

        return result;
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