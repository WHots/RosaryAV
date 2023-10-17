#include "antidbg.h"








void ScanPidForModules(DWORD processId)
{

	auto hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);

	size_t modsize = sizeof(processmods) / sizeof(processmods[0]);

	HMODULE hModules[1024];
	DWORD cbNeeded;

	if (K32EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded))
	{
		DWORD moduleCount = cbNeeded / sizeof(HMODULE);

		for (DWORD i = 0; i < moduleCount; i++)
		{
			wchar_t moduleName[MAX_PATH];

			if (K32GetModuleFileNameExW(hProcess, hModules[i], moduleName, sizeof(moduleName) / sizeof(TCHAR)))
			{
				for (auto i = 0; i < modsize; ++i)
				{
					if (wcsstr(moduleName, processmods[i]) != 0)
					{
						TerminateProcess(GetCurrentProcess(), 1);
					}
				}
			}
		}
	}

	return;
}


BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{

	auto length = GetWindowTextLengthA(hwnd);
	DWORD processId;

	if (length == 0)
	{
		return TRUE;
	}

	GetWindowThreadProcessId(hwnd, &processId);

	ScanPidForModules(processId);

	return TRUE;
}


bool VirtualizationEnabled()
{

	bool result = false;

#ifdef _MSC_VER
	int cpuInfo[4] = { 0 };
	__cpuid(cpuInfo, 1);
	result = (cpuInfo[2] & (1 << 5)) != 0;
#else
	bool hvSupported = false;
	asm volatile(
		"movl $1, %%eax\n\t"
		"cpuid\n\t"
		"testl $0x20, %%ecx\n\t"
		"setnz %0\n\t"
		: "=r" (hvSupported)
		:
		: "%eax", "%ebx", "%ecx", "%edx"
		);
	result = hvSupported;
#endif
	return result;
}


