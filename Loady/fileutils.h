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
#include "importmanager.h"

#pragma comment(lib, "Version.lib")


namespace fileutils
{
	/// <summary>
	/// Retrieves the full path of the executable file associated with the specified process.
	/// </summary>
	/// <param name="hProcess">The handle to the target process.</param>
	/// <param name="outPath">A reference to a std::wstring that will be used to store the full path of the executable file.</param>
	/// <returns>TRUE if the full path of the executable file was successfully retrieved, otherwise FALSE.</returns>
	BOOL GetExecutablePathName(const HANDLE hProcess, std::wstring& outPath);
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
	/// Checks if the specified file is patched (i.e., has the VS_FF_PATCHED flag set in the version information).
	/// </summary>
	/// <param name="filePath">The full path to the file to be checked.</param>
	/// <returns>
	/// 1 if the file is patched, 0 if the file is not patched, and -1 if an error occurred while retrieving the version information.
	/// </returns>
	int FilePatched(const wchar_t* filePath);
	/// <summary>
	/// Retrieves the security identifier (SID) of the owner of the specified file.
	/// </summary>
	/// <param name="filePath">The full path to the file.</param>
	/// <returns>
	/// A string containing the SID of the file owner, or an empty string if an error occurred.
	/// The caller is responsible for freeing the memory allocated for the SID string.
	/// </returns>
	std::wstring GetFileOwnerSid(const std::wstring& filePath);
	/// <summary>
	/// Determines if the file type is unknown based on its version information.
	/// </summary>
	/// <param name="filePath">The path to the file whose type is to be determined.</param>
	/// <returns>int: Returns 1 if the file type is unknown, 0 if the file type is known, 
	/// and -1 if unable to determine (e.g., if file version information is unavailable or an error occurs).</returns>
	int IsFileTypeUnknown(const wchar_t* filePath);
	/// <summary>
	/// Calculates the entropy of a file, which is a measure of the randomness in the file's data.
	/// </summary>
	/// <param name="filePath">The path to the file for which entropy is to be calculated.</param>
	/// <returns>double: The entropy value of the file. Ranges from 0 (completely predictable) to 8 (completely random for 8-bit bytes).</returns>
	double GetFileEntropy(const std::string& filePath);

}
