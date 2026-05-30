#pragma once
#include <windows.h>
#include <string>
#include <vector>

struct TpmPcrValue {
    UINT32  PcrIndex;
    UINT32  DigestSize;
    BYTE    Digest[64];
};

class TpmSeal {
public:
    static bool PcrRead(UINT32 pcrIndex, TpmPcrValue& out);
    static bool Seal(const std::vector<BYTE>& data, const std::vector<UINT32>& pcrs, std::vector<BYTE>& outBlob);
    static bool Unseal(const std::vector<BYTE>& blob, std::vector<BYTE>& outData);
    static bool GetEndorsementKey(std::vector<BYTE>& ekPub);
};

class Crypto {
public:
    static bool Sha256(const BYTE* data, size_t len, BYTE hash[32]);
    static bool Aes256GcmEncrypt(const BYTE* key, size_t keyLen, const BYTE* plaintext, size_t ptLen, std::vector<BYTE>& ciphertext);
    static bool Aes256GcmDecrypt(const BYTE* key, size_t keyLen, const BYTE* ciphertext, size_t ctLen, std::vector<BYTE>& plaintext);
};
