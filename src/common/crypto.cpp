#include "crypto.hpp"
#include <bcrypt.h>
#include <ncrypt.h>
#include <tbs.h>
#include <vector>
#include <iostream>

#pragma comment(lib, "bcrypt")
#pragma comment(lib, "ncrypt")
#pragma comment(lib, "tbs")

bool TpmSeal::PcrRead(UINT32 pcrIndex, TpmPcrValue& out) {
    TBS_HCONTEXT hContext = 0;
    TBS_CONTEXT_PARAMS params = { sizeof(TBS_CONTEXT_PARAMS), 0 };
    TBS_RESULT result = Tbsi_Context_Create(&params, &hContext);
    if (result != TBS_SUCCESS) return false;

    BYTE cmdBuf[256] = { 0 };
    BYTE rspBuf[4096] = { 0 };
    UINT32 rspLen = sizeof(rspBuf);

    UINT32 cmdSize = 0;
    cmdBuf[cmdSize++] = 0x80;
    cmdBuf[cmdSize++] = 0x02;
    cmdSize += 4;
    cmdBuf[cmdSize++] = 0x00;
    cmdBuf[cmdSize++] = 0x00;
    cmdBuf[cmdSize++] = 0x01;
    cmdBuf[cmdSize++] = 0x7e;
    cmdBuf[cmdSize++] = 0x00;
    cmdBuf[cmdSize++] = 0x00;
    cmdBuf[cmdSize++] = 0x00;
    cmdBuf[cmdSize++] = (BYTE)(pcrIndex & 0xff);
    cmdBuf[cmdSize++] = 0x00;
    cmdBuf[cmdSize++] = 0x00;
    cmdBuf[cmdSize++] = 0x00;
    cmdBuf[cmdSize++] = 0x01;
    cmdBuf[cmdSize++] = 0x00;
    cmdBuf[cmdSize++] = 0x0b;

    UINT32 len = cmdSize;
    cmdBuf[2] = (BYTE)((len >> 8) & 0xff);
    cmdBuf[3] = (BYTE)(len & 0xff);

    result = Tbsip_Submit_Command(hContext, TBS_COMMAND_LOCALITY_ZERO,
        TBS_COMMAND_PRIORITY_NORMAL, cmdBuf, cmdSize, rspBuf, &rspLen);
    Tbsip_Context_Close(hContext);

    if (result != TBS_SUCCESS) return false;

    out.PcrIndex = pcrIndex;
    out.DigestSize = 32;
    if (rspLen >= 28) {
        CopyMemory(out.Digest, rspBuf + rspLen - 32, 32);
    } else {
        return false;
    }
    return true;
}

bool TpmSeal::Seal(const std::vector<BYTE>& data, const std::vector<UINT32>& pcrs, std::vector<BYTE>& outBlob) {
    NCRYPT_PROV_HANDLE hProv = 0;
    SECURITY_STATUS status = NCryptOpenStorageProvider(&hProv, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0);
    if (status != ERROR_SUCCESS) return false;

    NCRYPT_KEY_HANDLE hKey = 0;
    status = NCryptOpenKey(hProv, &hKey, NCRYPT_SRK_KEY, 0, NCRYPT_SILENT_FLAG);
    if (status != ERROR_SUCCESS) { NCryptFreeObject(hProv); return false; }

    DWORD flags = NCRYPT_SILENT_FLAG;
    outBlob.resize(data.size() + 512);
    DWORD outSize = (DWORD)outBlob.size();

    status = NCryptEncrypt(hKey, data.data(), (DWORD)data.size(),
        NULL, outBlob.data(), (DWORD)outBlob.size(), &outSize, flags);
    if (status != ERROR_SUCCESS) { NCryptFreeObject(hKey); NCryptFreeObject(hProv); return false; }

    outBlob.resize(outSize);
    NCryptFreeObject(hKey);
    NCryptFreeObject(hProv);
    return true;
}

bool TpmSeal::Unseal(const std::vector<BYTE>& blob, std::vector<BYTE>& outData) {
    NCRYPT_PROV_HANDLE hProv = 0;
    SECURITY_STATUS status = NCryptOpenStorageProvider(&hProv, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0);
    if (status != ERROR_SUCCESS) return false;

    NCRYPT_KEY_HANDLE hKey = 0;
    status = NCryptOpenKey(hProv, &hKey, NCRYPT_SRK_KEY, 0, NCRYPT_SILENT_FLAG);
    if (status != ERROR_SUCCESS) { NCryptFreeObject(hProv); return false; }

    outData.resize(blob.size() + 256);
    DWORD outSize = (DWORD)outData.size();

    status = NCryptDecrypt(hKey, blob.data(), (DWORD)blob.size(),
        NULL, outData.data(), (DWORD)outData.size(), &outSize, NCRYPT_SILENT_FLAG);
    if (status != ERROR_SUCCESS) { NCryptFreeObject(hKey); NCryptFreeObject(hProv); return false; }

    outData.resize(outSize);
    NCryptFreeObject(hKey);
    NCryptFreeObject(hProv);
    return true;
}

bool TpmSeal::GetEndorsementKey(std::vector<BYTE>& ekPub) {
    NCRYPT_PROV_HANDLE hProv = 0;
    SECURITY_STATUS status = NCryptOpenStorageProvider(&hProv, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0);
    if (status != ERROR_SUCCESS) return false;

    NCRYPT_KEY_HANDLE hKey = 0;
    status = NCryptOpenKey(hProv, &hKey, NCRYPT_EK_KEY, 0, NCRYPT_SILENT_FLAG);
    if (status != ERROR_SUCCESS) { NCryptFreeObject(hProv); return false; }

    ekPub.resize(1024);
    DWORD outSize = (DWORD)ekPub.size();
    status = NCryptExportKey(hKey, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, ekPub.data(), (DWORD)ekPub.size(), &outSize, 0);
    if (status != ERROR_SUCCESS) { NCryptFreeObject(hKey); NCryptFreeObject(hProv); return false; }

    ekPub.resize(outSize);
    NCryptFreeObject(hKey);
    NCryptFreeObject(hProv);
    return true;
}

bool Crypto::Sha256(const BYTE* data, size_t len, BYTE hash[32]) {
    BCRYPT_ALG_HANDLE hAlg = 0;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return false;
    status = BCryptHash(hAlg, NULL, 0, (PUCHAR)data, (ULONG)len, hash, 32);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return BCRYPT_SUCCESS(status);
}

bool Crypto::Aes256GcmEncrypt(const BYTE* key, size_t keyLen, const BYTE* plaintext, size_t ptLen, std::vector<BYTE>& ciphertext) {
    BCRYPT_ALG_HANDLE hAlg = 0;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return false;
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    DWORD keyObjLen = 0, cbResult = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjLen, sizeof(keyObjLen), &cbResult, 0);

    std::vector<BYTE> keyObj(keyObjLen);
    BCRYPT_KEY_HANDLE hKey = 0;
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjLen, (PUCHAR)key, (ULONG)keyLen, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    BYTE nonce[12];
    BCryptGenRandom(NULL, nonce, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = 12;
    authInfo.pbTag = NULL;
    authInfo.cbTag = 0;

    ciphertext.resize(ptLen + 12 + 16);
    CopyMemory(ciphertext.data(), nonce, 12);
    ULONG outSize = 0;

    status = BCryptEncrypt(hKey, (PUCHAR)plaintext, (ULONG)ptLen,
        &authInfo, ciphertext.data() + 12, (ULONG)(ciphertext.size() - 12),
        ciphertext.data() + 12, (ULONG)(ciphertext.size() - 12), &outSize, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    ciphertext.resize(12 + outSize + 16);
    authInfo.pbTag = ciphertext.data() + 12 + outSize;
    authInfo.cbTag = 16;
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return true;
}

bool Crypto::Aes256GcmDecrypt(const BYTE* key, size_t keyLen, const BYTE* ciphertext, size_t ctLen, std::vector<BYTE>& plaintext) {
    if (ctLen < 12 + 16) return false;
    BCRYPT_ALG_HANDLE hAlg = 0;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return false;
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    DWORD keyObjLen = 0, cbResult = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjLen, sizeof(keyObjLen), &cbResult, 0);
    std::vector<BYTE> keyObj(keyObjLen);
    BCRYPT_KEY_HANDLE hKey = 0;
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjLen, (PUCHAR)key, (ULONG)keyLen, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)ciphertext;
    authInfo.cbNonce = 12;
    ULONG ctDataLen = (ULONG)(ctLen - 12 - 16);
    authInfo.pbTag = (PUCHAR)(ciphertext + 12 + ctDataLen);
    authInfo.cbTag = 16;

    plaintext.resize(ctDataLen + 16);
    ULONG outSize = 0;
    status = BCryptDecrypt(hKey, (PUCHAR)(ciphertext + 12), ctDataLen,
        &authInfo, plaintext.data(), (ULONG)plaintext.size(),
        plaintext.data(), (ULONG)plaintext.size(), &outSize, 0);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!BCRYPT_SUCCESS(status)) return false;
    plaintext.resize(outSize);
    return true;
}
