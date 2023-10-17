#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <intrin.h>




const static wchar_t* processmods[] =
{
	L"TitanEngine",
	L"x64_dbg",
	L"Themida",
	L"Qt5Core",
	L"Qt4Core",
	L"ida64",
	L"Scylla",
	L"lua53-64",
	L"tcc64-64"
};


void ScanPidForModules(DWORD pid);
bool VirtualizationEnabled();