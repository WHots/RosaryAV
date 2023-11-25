#include "strutils.h"




namespace stringutil
{


    int StringLengthA(char* str)
    {
        int length;
        for (length = 0; str[length] != '\0'; length++) {}
        return length;
    }


    wchar_t* CStringToWide(char* str)
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

        int bufferSize = MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), -1, nullptr, 0);

        if (bufferSize == 0)         
            return std::wstring();

        std::wstring wideString(bufferSize, 0);


        if (MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), -1, &wideString[0], bufferSize) == 0)
            return std::wstring();


        wideString.pop_back();
        return wideString;
    }


    std::string WideStringToUTF8(const wchar_t* wideString)
    {       

        int bufferSize = WideCharToMultiByte(CP_UTF8, 0, wideString, -1, nullptr, 0, nullptr, nullptr);

        if (bufferSize == 0)
            return std::string();    

        std::string multiByteString(bufferSize, 0);

        if (WideCharToMultiByte(CP_UTF8, 0, wideString, -1, &multiByteString[0], bufferSize, nullptr, nullptr) == 0)
            return std::string();


        multiByteString.pop_back();
        return multiByteString;
    }
}
