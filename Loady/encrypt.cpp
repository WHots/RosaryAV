#include "encrypt.h"
#include "strutils.h"





std::string ChaChaEncrypt(const std::wstring& plaintext, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv) 
{

    CryptoPP::AutoSeededRandomPool rng;
    key = CryptoPP::SecByteBlock(CryptoPP::ChaCha::DEFAULT_KEYLENGTH);
    iv = CryptoPP::SecByteBlock(CryptoPP::ChaCha::IV_LENGTH);

    rng.GenerateBlock(key, key.size());
    rng.GenerateBlock(iv, iv.size());

    std::string utf8Plaintext = stringutil::WideToUTF8(plaintext);
    CryptoPP::ChaCha::Encryption chachaEncryption(key, key.size(), iv);

    std::string ciphertext;
    CryptoPP::StringSource(utf8Plaintext, true,
        new CryptoPP::StreamTransformationFilter(chachaEncryption,
            new CryptoPP::StringSink(ciphertext)
        )
    );

    return ciphertext;
}


std::wstring ChaChaDecrypt(const std::string& ciphertext, const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv) 
{

    CryptoPP::ChaCha::Decryption chachaDecryption(key, key.size(), iv);

    std::string decryptedText;
    CryptoPP::StringSource(ciphertext, true,
        new CryptoPP::StreamTransformationFilter(chachaDecryption,
            new CryptoPP::StringSink(decryptedText)
        )
    );

    return stringutil::UTF8ToWide(decryptedText);
}


