#include "crypto.hpp"
#include <bcrypt.h>
#include <tbs.h>
#include <vector>
#include <stdexcept>

#pragma comment(lib, "bcrypt")
#pragma comment(lib, "tbs")

static const BYTE TPM_SEAL_PCRS[] = { 0, 2, 4, 7, 11 };

bool TpmSeal::PcrRead(UINT32 pcrIndex, TpmPcrValue& out) {
    TBS_HCONTEXT hContext = 0;
    TBS_CONTEXT_PARAMS params = { sizeof(TBS_CONTEXT_PARAMS), TBS_TCG_VERSION_2 };
    TBS_RESULT result = Tbsi_Context_Create(&params, &hContext);
    if (result != TBS_SUCCESS) return false;

    TPMS_CONTEXT tpmContext;
    UINT32 contextSize = sizeof(tpmContext);
    result = Tbsi_Context_Create(&params, &hContext);
    if (result != TBS_SUCCESS) return false;

    BYTE pcrSelect[3] = { 0 };
    pcrSelect[pcrIndex / 8] |= (1 << (pcrIndex % 8));

    UINT32 pcrCount = 1;
    UINT32 outSize = sizeof(TPM2B_DIGEST) + sizeof(TPML_PCR_SELECTION);
    std::vector<BYTE> buffer(outSize);
    UINT32 respSize = 0;

    TPML_PCR_SELECTION pcrSelIn = { 1 };
    pcrSelIn.pcrSelections[0].hash = TPM_ALG_SHA256;
    pcrSelIn.pcrSelections[0].sizeofSelect = 3;
    pcrSelIn.pcrSelections[0].pcrSelect[0] = pcrSelect[0];
    pcrSelIn.pcrSelections[0].pcrSelect[1] = pcrSelect[1];
    pcrSelIn.pcrSelections[0].pcrSelect[2] = pcrSelect[2];

    TSS2_SYS_CMD_AUTHORIZATION auth = { 0 };
    UINT32 cmdSize = sizeof(TPM2B_DIGEST) + sizeof(TPML_PCR_SELECTION) + 16;
    std::vector<BYTE> cmdBuf(cmdSize);
    UINT32 rspSize = 0;
    std::vector<BYTE> rspBuf(4096);

    result = Tbsi_Context_Create(&params, &hContext);
    if (result != TBS_SUCCESS) {
        Tbsi_Context_Create(&params, &hContext);
    }

    BYTE protocolBuf[4096];
    UINT32 protocolSize = sizeof(protocolBuf);

    result = Tbsip_Submit_Command(hContext, TBS_COMMAND_PRIORITY_NORMAL,
        protocolBuf, protocolSize, protocolBuf, &protocolSize);

    if (result != TBS_SUCCESS) {
        Tbsip_Context_Close(hContext);
        return false;
    }

    out.PcrIndex = pcrIndex;
    out.DigestSize = 32;
    ZeroMemory(out.Digest, sizeof(out.Digest));
    CopyMemory(out.Digest, protocolBuf + sizeof(TPM2B_DIGEST), min(32, protocolSize - sizeof(TPM2B_DIGEST)));

    Tbsip_Context_Close(hContext);
    return true;
}

bool TpmSeal::Seal(const std::vector<BYTE>& data, const std::vector<UINT32>& pcrs, std::vector<BYTE>& outBlob) {
    NCRYPT_PROV_HANDLE hProv = 0;
    SECURITY_STATUS status = NCryptOpenStorageProvider(&hProv, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0);
    if (status != ERROR_SUCCESS) return false;

    NCRYPT_KEY_HANDLE hKey = 0;
    status = NCryptOpenKey(hProv, &hKey, L"TPM_SRK", 0, NCRYPT_SILENT_FLAG);
    if (status != ERROR_SUCCESS) {
        NCryptFreeObject(hProv);
        return false;
    }

    std::vector<BYTE> pcrBlob;
    for (auto pcr : pcrs) {
        TpmPcrValue val;
        if (PcrRead(pcr, val)) {
            pcrBlob.insert(pcrBlob.end(), val.Digest, val.Digest + val.DigestSize);
        }
    }

    std::vector<BYTE> authPolicy;
    outBlob.resize(data.size() + 256);
    DWORD outSize = (DWORD)outBlob.size();

    status = NCryptEncrypt(hKey, data.data(), (DWORD)data.size(),
        NULL, outBlob.data(), (DWORD)outBlob.size(), &outSize, NCRYPT_SILENT_FLAG | NCRYPT_PAD_PCR_FLAG);
    if (status != ERROR_SUCCESS) {
        NCryptFreeObject(hKey);
        NCryptFreeObject(hProv);
        return false;
    }

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
    status = NCryptOpenKey(hProv, &hKey, L"TPM_SRK", 0, NCRYPT_SILENT_FLAG);
    if (status != ERROR_SUCCESS) {
        NCryptFreeObject(hProv);
        return false;
    }

    outData.resize(blob.size() + 256);
    DWORD outSize = (DWORD)outData.size();

    status = NCryptDecrypt(hKey, blob.data(), (DWORD)blob.size(),
        NULL, outData.data(), (DWORD)outData.size(), &outSize,
        NCRYPT_SILENT_FLAG | NCRYPT_PAD_PCR_FLAG);
    if (status != ERROR_SUCCESS) {
        NCryptFreeObject(hKey);
        NCryptFreeObject(hProv);
        return false;
    }

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
    status = NCryptOpenKey(hProv, &hKey, L"TPM_EK", 0, NCRYPT_SILENT_FLAG);
    if (status != ERROR_SUCCESS) {
        NCryptFreeObject(hProv);
        return false;
    }

    ekPub.resize(1024);
    DWORD outSize = (DWORD)ekPub.size();
    status = NCryptExportKey(hKey, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, ekPub.data(), (DWORD)ekPub.size(), &outSize, 0);
    if (status != ERROR_SUCCESS) {
        NCryptFreeObject(hKey);
        NCryptFreeObject(hProv);
        return false;
    }

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
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    DWORD keyObjLen = 0;
    DWORD cbResult = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjLen, sizeof(keyObjLen), &cbResult, 0);

    DWORD tagLen = 16;
    DWORD nonceLen = 12;

    std::vector<BYTE> keyObj(keyObjLen);
    BCRYPT_KEY_HANDLE hKey = 0;
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjLen, (PUCHAR)key, (ULONG)keyLen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

    BYTE nonce[12];
    BCryptGenRandom(NULL, nonce, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = nonceLen;
    authInfo.pbTag = NULL;
    authInfo.cbTag = 0;

    ciphertext.resize(ptLen + 12 + 16);
    CopyMemory(ciphertext.data(), nonce, 12);

    ULONG outSize = 0;
    status = BCryptEncrypt(hKey, (PUCHAR)plaintext, (ULONG)ptLen,
        &authInfo, ciphertext.data() + 12, (ULONG)(ciphertext.size() - 12),
        ciphertext.data() + 12, (ULONG)(ciphertext.size() - 12), &outSize,
        BCRYPT_BLOCK_PADDING);

    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

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
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    DWORD keyObjLen = 0;
    DWORD cbResult = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjLen, sizeof(keyObjLen), &cbResult, 0);

    std::vector<BYTE> keyObj(keyObjLen);
    BCRYPT_KEY_HANDLE hKey = 0;
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), keyObjLen, (PUCHAR)key, (ULONG)keyLen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

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
        plaintext.data(), (ULONG)plaintext.size(), &outSize,
        BCRYPT_BLOCK_PADDING);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) return false;
    plaintext.resize(outSize);
    return true;
}
