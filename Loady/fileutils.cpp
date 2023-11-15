#include "fileutils.h"








BOOL GetExecutablePathName(HANDLE hProcess, std::string& outPath)
{

    wchar_t buffer[MAX_PATH];

    DWORD result = K32GetModuleFileNameExW(hProcess, NULL, buffer, MAX_PATH);

    if (result != 0) 
    {
        std::wstring wstr(buffer);
        outPath.assign(wstr.begin(), wstr.end());
    }
    return (result != 0);
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

    void* buffer;
    UINT length;
    
    if (VerQueryValueW(data.data(), TEXT("\\StringFileInfo\\040904b0\\InternalName"), &buffer, &length))
        internalName = stringutil::WideStringToUTF8(static_cast<wchar_t*>(buffer));
    
    return internalName;
}