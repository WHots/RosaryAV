#pragma once
#include <Windows.h>
#include <tchar.h>
#include <string>
#include <Psapi.h>
#include <filesystem>
#include <codecvt>

#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

#include "strutils.h"

#pragma comment(lib, "Version.lib")


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