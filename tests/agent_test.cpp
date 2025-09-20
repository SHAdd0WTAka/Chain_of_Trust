#include <gtest/gtest.h>
#include "../src/common/crypto.hpp"
TEST(CryptoTest, EncryptDecrypt) {
    std::string input = "ChainOfTrust";
    auto encrypted = Encrypt(input);
    auto decrypted = Decrypt(encrypted);
    ASSERT_EQ(decrypted, input);
}
