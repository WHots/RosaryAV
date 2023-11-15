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
    wchar_t* CharToWChar_T(char* str);
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
