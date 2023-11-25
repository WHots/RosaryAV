#pragma once
#include <Windows.h>
#include <string>
#include <random>
#include <codecvt>


#define WIDESTRING_COMPARE(s1, s2) _wcsicmp(s1, s2)




namespace stringutil
{
    /// <summary>
    /// Returns ANS string length.
    /// </summary>
    /// <param name="str">string data.</param>
    /// <returns>String length.</returns>
    int StringLengthA(char* str);
    /// <summary>
    /// Converts a char* into wide.
    /// </summary>
    /// <param name="str">string data,</param>
    /// <returns>String data as a wide string.</returns>
    wchar_t* CStringToWide(char* str);
    /// <summary>
    /// Converts UTF-8 string into wide.
    /// </summary>
    /// <param name="utf8Str">Generic UTF-8 string.</param>
    /// <returns>Wide string variant.</returns>
    std::wstring UTF8ToWide(const std::string& utf8Str);
    /// <summary>
    /// Converts wide string into UTF-8.
    /// </summary>
    /// <param name="utf8Str">Generic wide string.</param>
    /// <returns>UTF-8 string variant.</returns>
    std::string WideStringToUTF8(const wchar_t* wideString);
}




/// <summary>
/// The SecureBstr class is a template-based utility designed to securely handle BSTR strings in C++.
/// It ensures that sensitive data stored in these strings is securely cleared and freed from memory 
/// when no longer needed. The class is capable of handling both narrow (char) and wide (wchar_t) character 
/// types, automatically managing the memory of the underlying BSTR to prevent data leaks.
///
/// Key features include automatic clearing and freeing of memory on object destruction, move semantics 
/// support for safe transfer of data ownership, and deletion of copy semantics to prevent inadvertent 
/// data duplication. It is particularly useful in scenarios where handling sensitive information like 
/// passwords or personal data is required.
/// </summary>
/// <typeparam name="T">Character type, either wchar_t for wide strings or char for narrow strings.</typeparam>
/// <remarks>
/// The class deletes the copy constructor and copy assignment operator to prevent inadvertent copying 
/// of sensitive data, aligning with secure coding practices. It, however, supports move semantics, 
/// allowing ownership of the data to be transferred safely without duplicating the sensitive content.
/// The class provides a 'get' method to access the underlying BSTR, but caution should be exercised 
/// to avoid exposing sensitive data. This class is not suitable for use in standard containers that 
/// require copy or assignment operations.
/// </remarks>
/// 
/// <example>
/// Usage:
///   std::wstring wideString = L"test";
///   SecureBstr<wchar_t> secureWideString(wideString);
///
///   std::string narrowString = "test";
///   SecureBstr<char> secureNarrowString(narrowString);
///
///   BSTR bstr = secureWideString.get();
///   SecureBstr<wchar_t> movedString = std::move(secureWideString);
/// </example>
template <typename T>
class SecureBstr 
{

    BSTR bstr;
    size_t length;


    void clearAndFree()
    {
        if (bstr != nullptr)
        {
            memset(bstr, 0, length);
            SysFreeString(bstr);
            bstr = nullptr;
            length = 0;
        }
    }


public:
   

    SecureBstr(const std::basic_string<T>& str) 
    {

        if constexpr (std::is_same<T, wchar_t>::value)        
            bstr = SysAllocString(str.c_str());   
        else 
        {
            std::wstring wideStr(str.begin(), str.end());
            bstr = SysAllocString(wideStr.c_str());
        }

        length = SysStringByteLen(bstr);
    }


    ~SecureBstr() 
    {
        clearAndFree();
    }


    SecureBstr(const SecureBstr&) = delete;
    SecureBstr& operator=(const SecureBstr&) = delete;


    SecureBstr(SecureBstr&& other) noexcept : bstr(other.bstr), length(other.length) 
    {
        other.bstr = nullptr;
        other.length = 0;
    }

    SecureBstr& operator=(SecureBstr&& other) noexcept
    {

        if (this != &other) 
        {
            clearAndFree();
            bstr = other.bstr;
            length = other.length;
            other.bstr = nullptr;
            other.length = 0;
        }

        return *this;
    }


    BSTR get() const 
    {
        return bstr;
    }
};