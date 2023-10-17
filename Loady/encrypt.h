#pragma once
#include <Windows.h>
#include <iostream>
#include <cryptopp/chacha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/chachapoly.h>
#include <random>
#include <codecvt>




/// <summary>
/// Returns an encrypted ChaCha string.
/// </summary>
/// <param name="plaintext">String to be encrypted.</param>
/// <param name="key">ChaCha key.</param>
/// <param name="iv">ChaCha iv</param>
/// <returns>Returns an encrypted ChaCha string.</returns>
std::string ChaChaEncrypt(const std::wstring& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
/// <summary>
/// Decrypts an encrypted ChaCha string.
/// </summary>
/// <param name="ciphertext">Encrypted string to be decrypted.</param>
/// <param name="key">ChaCha key.</param>
/// <param name="iv">ChaCha IV.</param>
/// <returns>Returns the decrypted ChaCha string.</returns>
std::wstring ChaChaDecrypt(const std::string& ciphertext, const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv);
