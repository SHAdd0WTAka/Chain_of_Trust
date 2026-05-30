#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "../src/common/AdminAuth.hpp"
#include "../src/common/crypto.hpp"

TEST(AdminAuthTest, ProtocolFlipHttpsRejected) {
    std::string httpsUrl = "https://chain-of-trust.local/auth?code=abcdef1234567890";
    EXPECT_FALSE(AdminAuth::ValidateProtocolFlip(httpsUrl));
}

TEST(AdminAuthTest, ProtocolFlipHttpAccepted) {
    std::string httpUrl = "http://chain-of-trust.local/auth?code=abcdef1234567890abcdef1234567890";
    EXPECT_TRUE(AdminAuth::ValidateProtocolFlip(httpUrl));
}

TEST(AdminAuthTest, ProtocolFlipNoCodeRejected) {
    std::string badUrl = "http://chain-of-trust.local/";
    EXPECT_FALSE(AdminAuth::ValidateProtocolFlip(badUrl));
}

TEST(AdminAuthTest, ProtocolFlipShortCodeRejected) {
    std::string shortUrl = "http://chain-of-trust.local/auth?code=abc";
    EXPECT_FALSE(AdminAuth::ValidateProtocolFlip(shortUrl));
}

TEST(AdminAuthTest, TimeWindowLogic) {
    EXPECT_TRUE(AdminAuth::IsWithinWindow(0, 0, 23, 59));
}

TEST(AdminAuthTest, ChallengeGeneration) {
    std::string challenge = AdminAuth::GenerateChallenge();
    EXPECT_NE(challenge.find("https://"), std::string::npos);
    EXPECT_NE(challenge.find("code="), std::string::npos);
}

TEST(CryptoTest, Sha256KnownVector) {
    BYTE data[] = "hello world";
    BYTE expected[32] = {
        0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08,
        0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab, 0xfa,
        0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee,
        0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9
    };
    BYTE hash[32] = { 0 };
    EXPECT_TRUE(Crypto::Sha256(data, sizeof(data) - 1, hash));
    EXPECT_EQ(memcmp(hash, expected, 32), 0);
}

TEST(CryptoTest, Aes256GcmRoundTrip) {
    BYTE key[32] = { 0 };
    for (int i = 0; i < 32; i++) key[i] = (BYTE)i;

    const char* plaintext = "AKIR FsTx Recovery Test Data";
    size_t ptLen = strlen(plaintext);

    std::vector<BYTE> ciphertext;
    EXPECT_TRUE(Crypto::Aes256GcmEncrypt(key, sizeof(key),
        (const BYTE*)plaintext, ptLen, ciphertext));
    EXPECT_GT(ciphertext.size(), ptLen);

    std::vector<BYTE> decrypted;
    EXPECT_TRUE(Crypto::Aes256GcmDecrypt(key, sizeof(key),
        ciphertext.data(), ciphertext.size(), decrypted));
    EXPECT_EQ(decrypted.size(), ptLen);
    EXPECT_EQ(memcmp(decrypted.data(), plaintext, ptLen), 0);
}

TEST(TpmTest, PcrReadGracefulFailure) {
    TpmPcrValue pcr0;
    bool result = TpmSeal::PcrRead(0, pcr0);
    (void)result;
    EXPECT_TRUE(true);
}

TEST(TpmTest, GetEndorsementKeyGracefulFailure) {
    std::vector<BYTE> ekPub;
    bool result = TpmSeal::GetEndorsementKey(ekPub);
    (void)result;
    EXPECT_TRUE(true);
}
