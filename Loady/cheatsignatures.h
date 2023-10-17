#pragma once
#include <array>



struct CryptoElements
{
	const wchar_t* name;
	const char* pattern;
};


constexpr std::array<CryptoElements, 4> loaders = 
{
	{
		L"Random Pasted p2c name here",
		//	...
	},
};