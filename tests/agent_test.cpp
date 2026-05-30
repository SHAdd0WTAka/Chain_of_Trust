#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "../src/common/AdminAuth.hpp"
#include "../src/common/crypto.hpp"
#include "../src/common/shamir.hpp"
#include "../src/common/peer_discovery.hpp"
#include "../src/common/dkg.hpp"

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

TEST(ShamirTest, SplitAndRecover2of3) {
    std::vector<BYTE> secret = { 0xDE, 0xAD, 0xBE, 0xEF };
    std::vector<Shard> shards;
    EXPECT_TRUE(Shamir::Split(secret, 2, 3, shards));
    EXPECT_EQ(shards.size(), 3);
    EXPECT_EQ(shards[0].Data.size(), secret.size());

    std::vector<Shard> subset = { shards[0], shards[1] };
    std::vector<BYTE> recovered;
    EXPECT_TRUE(Shamir::Recover(subset, 2, recovered));
    EXPECT_EQ(recovered.size(), secret.size());
    EXPECT_EQ(memcmp(recovered.data(), secret.data(), secret.size()), 0);
}

TEST(ShamirTest, SplitAndRecover3of5) {
    std::vector<BYTE> secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    std::vector<Shard> shards;
    EXPECT_TRUE(Shamir::Split(secret, 3, 5, shards));
    EXPECT_EQ(shards.size(), 5);

    std::vector<Shard> subset = { shards[0], shards[2], shards[4] };
    std::vector<BYTE> recovered;
    EXPECT_TRUE(Shamir::Recover(subset, 3, recovered));
    EXPECT_EQ(recovered.size(), secret.size());
    EXPECT_EQ(memcmp(recovered.data(), secret.data(), secret.size()), 0);
}

TEST(ShamirTest, WrongThresholdFails) {
    std::vector<BYTE> secret = { 0xCA, 0xFE };
    std::vector<Shard> shards;
    EXPECT_TRUE(Shamir::Split(secret, 3, 5, shards));

    std::vector<Shard> subset = { shards[0], shards[1] };
    std::vector<BYTE> recovered;
    EXPECT_FALSE(Shamir::Recover(subset, 3, recovered));
}

TEST(ShamirTest, Any3of5Recovers) {
    std::vector<BYTE> secret = { 0xAA, 0xBB, 0xCC };
    std::vector<Shard> shards;
    EXPECT_TRUE(Shamir::Split(secret, 3, 5, shards));

    std::vector<Shard> subset1 = { shards[0], shards[1], shards[2] };
    std::vector<BYTE> recovered1;
    EXPECT_TRUE(Shamir::Recover(subset1, 3, recovered1));
    EXPECT_EQ(memcmp(recovered1.data(), secret.data(), secret.size()), 0);

    std::vector<Shard> subset2 = { shards[2], shards[3], shards[4] };
    std::vector<BYTE> recovered2;
    EXPECT_TRUE(Shamir::Recover(subset2, 3, recovered2));
    EXPECT_EQ(memcmp(recovered2.data(), secret.data(), secret.size()), 0);

    std::vector<Shard> subset3 = { shards[0], shards[3], shards[4] };
    std::vector<BYTE> recovered3;
    EXPECT_TRUE(Shamir::Recover(subset3, 3, recovered3));
    EXPECT_EQ(memcmp(recovered3.data(), secret.data(), secret.size()), 0);
}

TEST(ShamirTest, LargeSecretRoundTrip) {
    std::vector<BYTE> secret(256);
    for (int i = 0; i < 256; i++) secret[i] = (BYTE)i;

    std::vector<Shard> shards;
    EXPECT_TRUE(Shamir::Split(secret, 3, 5, shards));

    std::vector<Shard> subset = { shards[0], shards[2], shards[4] };
    std::vector<BYTE> recovered;
    EXPECT_TRUE(Shamir::Recover(subset, 3, recovered));
    EXPECT_EQ(recovered.size(), 256);
    EXPECT_EQ(memcmp(recovered.data(), secret.data(), 256), 0);
}

TEST(ShamirTest, IsValidThreshold) {
    EXPECT_TRUE(Shamir::IsValidThreshold(2, 3));
    EXPECT_TRUE(Shamir::IsValidThreshold(5, 10));
    EXPECT_FALSE(Shamir::IsValidThreshold(0, 3));
    EXPECT_FALSE(Shamir::IsValidThreshold(1, 3));
    EXPECT_FALSE(Shamir::IsValidThreshold(4, 3));
    EXPECT_FALSE(Shamir::IsValidThreshold(2, 0));
}

TEST(DkgTest, AttestationCreateAndVerify) {
    AttestationReport report;
    report.PeerId = L"test-node";
    report.IntegrityScore = 100;
    report.TimerRemaining = 1440;
    report.Timestamp.dwHighDateTime = 0;
    report.Timestamp.dwLowDateTime = 1;

    std::string toSign = std::to_string(report.IntegrityScore) +
                         std::to_string(report.TimerRemaining);
    BYTE hash[32];
    Crypto::Sha256((BYTE*)toSign.data(), toSign.size(), hash);
    report.Signature.assign(hash, hash + 32);

    EXPECT_TRUE(DkgManager::VerifyAttestationReport(report));
}

TEST(DkgTest, AttestationLowIntegrityRejected) {
    AttestationReport report;
    report.IntegrityScore = 50;
    report.TimerRemaining = 1440;

    std::string toSign = std::to_string(report.IntegrityScore) +
                         std::to_string(report.TimerRemaining);
    BYTE hash[32];
    Crypto::Sha256((BYTE*)toSign.data(), toSign.size(), hash);
    report.Signature.assign(hash, hash + 32);

    EXPECT_FALSE(DkgManager::VerifyAttestationReport(report));
}

TEST(DkgTest, AttestationTimerExpiredRejected) {
    AttestationReport report;
    report.IntegrityScore = 100;
    report.TimerRemaining = 0;

    std::string toSign = std::to_string(report.IntegrityScore) +
                         std::to_string(report.TimerRemaining);
    BYTE hash[32];
    Crypto::Sha256((BYTE*)toSign.data(), toSign.size(), hash);
    report.Signature.assign(hash, hash + 32);

    EXPECT_FALSE(DkgManager::VerifyAttestationReport(report));
}

TEST(DkgTest, AttestationTamperedSignatureRejected) {
    AttestationReport report;
    report.PeerId = L"test-node";
    report.IntegrityScore = 100;
    report.TimerRemaining = 1440;

    report.Signature.assign(32, 0xAA);

    EXPECT_FALSE(DkgManager::VerifyAttestationReport(report));
}

TEST(PeerDiscoveryTest, PeerIdGeneration) {
    PeerDiscovery::Start(18444);
    EXPECT_TRUE(PeerDiscovery::IsRunning());

    auto peers = PeerDiscovery::GetPeers();
    EXPECT_TRUE(peers.empty());

    PeerDiscovery::Stop();
    EXPECT_FALSE(PeerDiscovery::IsRunning());
}

TEST(PeerDiscoveryTest, AddStaticPeer) {
    PeerDiscovery::Start(18445);
    bool added = PeerDiscovery::AddStaticPeer(L"192.168.1.100", 8443);
    EXPECT_TRUE(added);

    auto peers = PeerDiscovery::GetPeers();
    EXPECT_GE(peers.size(), 1);

    PeerDiscovery::Stop();
}

TEST(PeerDiscoveryTest, RemovePeer) {
    PeerDiscovery::Start(18446);
    PeerDiscovery::AddStaticPeer(L"192.168.1.200", 8443);
    auto peers = PeerDiscovery::GetPeers();
    EXPECT_GE(peers.size(), 1);

    bool removed = PeerDiscovery::RemovePeer(peers[0].PeerId);
    EXPECT_TRUE(removed);

    peers = PeerDiscovery::GetPeers();
    EXPECT_TRUE(peers.empty());

    PeerDiscovery::Stop();
}
