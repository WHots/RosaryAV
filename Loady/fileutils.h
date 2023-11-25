#pragma once
#include <Windows.h>
#include <tchar.h>
#include <string>
#include <array>
#include <Psapi.h>
#include <filesystem>
#include <codecvt>

#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

#include "strutils.h"
#include "memutils.h"

#pragma comment(lib, "Version.lib")


namespace fileutils
{

	/// <summary>
	/// Retrieves the full path of the executable file of a specified process.
	/// </summary>
	/// <param name="hProcess">Handle to the process.</param>
	/// <param name="outPath">String to store the path of the executable file.</param>
	/// <returns>TRUE if the path is successfully retrieved, otherwise FALSE.</returns>
	BOOL GetExecutablePathName(HANDLE hProcess, std::string& outPath);
	/// <summary>
	/// Calculates the MD5 hash of a file.
	/// </summary>
	/// <param name="fileName">The path of the file to calculate the MD5 hash for.</param>
	/// <returns>A string representing the hexadecimal MD5 hash of the file.</returns>
	std::string CalculateFileMD5(const std::string& fileName);
	/// <summary>
	/// Extracts the stem (the part of the path before the last dot) of a file path.
	/// </summary>
	/// <param name="filePath">The file path to extract the stem from.</param>
	/// <returns>The stem of the file path.</returns>
	std::string GetFileStemName(const std::string& filePath);
	/// <summary>
	/// Retrieves the internal name of a file, typically specified in the file's metadata.
	/// </summary>
	/// <param name="filePath">The path to the file for which the internal name is requested.</param>
	/// <returns>std::string: Returns the internal name of the file as a string. otherwise, empty string.</returns>
	std::string GetFileInternalName(const wchar_t* filePath);
	/// <summary>
	/// Checks if a file has been patched by examining the file's version information.
	/// </summary>
	/// <param name="filePath">The path to the file to be checked for patches.</param>
	/// <returns>int: Returns 1 if the file is patched, 0 if not patched, and -1 if unable to determine (e.g., if file version information is unavailable or an error occurs).</returns>
	int FilePatched(const wchar_t* filePath);
	/// <summary>
	/// Retrieves the security identifier (SID) of the owner of a file.
	/// </summary>
	/// <param name="filePath">A pointer to a null-terminated string that specifies the path of the file.</param>
	/// <returns>A pointer to a null-terminated string representing the SID of the file's owner.
	/// Returns nullptr if the function fails. The caller is responsible for freeing the
	/// returned string using the standard C library function free.</returns>
	/// <remarks>
	/// This function dynamically imports the GetNamedSecurityInfoW function from advapi32.dll to
	/// retrieve the owner SID of the specified file. It then converts this SID to a string format
	/// for easier handling. The function handles memory allocation and freeing internally, but
	/// the caller is responsible for freeing the returned SID string. If the function fails at
	/// any step (e.g., dynamic import failure, retrieval failure, conversion failure), it returns
	/// nullptr. The function uses smart pointers for automatic resource management.
	/// </remarks>
	LPTSTR GetFileOwnerSid(const wchar_t* filePath);
	/// <summary>
	/// Determines if the file type is unknown based on its version information.
	/// </summary>
	/// <param name="filePath">The path to the file whose type is to be determined.</param>
	/// <returns>int: Returns 1 if the file type is unknown, 0 if the file type is known, 
	/// and -1 if unable to determine (e.g., if file version information is unavailable or an error occurs).</returns>
	int IsFileTypeUnknown(const wchar_t* filePath);
	/// <summary>
	/// Calculates the entropy of a file, which is a measure of the randomness in the file's data.
	/// Useful for detecting compressed or encrypted files.
	/// </summary>
	/// <param name="filePath">The path to the file for which entropy is to be calculated.</param>
	/// <returns>double: The entropy value of the file. Ranges from 0 (completely predictable) to 8 (completely random for 8-bit bytes).</returns>
	double GetFileEntropy(const std::string& filePath);

}