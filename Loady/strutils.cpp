#include "strutils.h"




namespace stringutil
{


    int StringLengthA(char* str)
    {
        int length;
        for (length = 0; str[length] != '\0'; length++) {}
        return length;
    }


    wchar_t* CharToWChar_T(char* str)
    {
        int length = StringLengthA(str);
        if (str == nullptr) {
            return nullptr;
        }

        wchar_t* wstr_t = (wchar_t*)malloc(sizeof(wchar_t) * (length + 1));

        for (int i = 0; i < length; i++) {
            wstr_t[i] = str[i];
        }
        wstr_t[length] = L'\0';
        return wstr_t;
    }


    std::wstring UTF8ToWide(const std::string& utf8Str)
    {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        return converter.from_bytes(utf8Str);
    }


    std::string WideToUTF8(const std::wstring& wideStr)
    {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        return converter.to_bytes(wideStr);
    }
}
