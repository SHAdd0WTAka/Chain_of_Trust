#pragma once
#include <windows.h>
#include <vector>
#include <string>

struct Shard {
    BYTE ParticipantId;
    std::vector<BYTE> Data;
};

class Shamir {
public:
    static bool Split(const std::vector<BYTE>& secret, BYTE threshold, BYTE total, std::vector<Shard>& outShards);
    static bool Recover(const std::vector<Shard>& shards, BYTE threshold, std::vector<BYTE>& outSecret);
    static bool IsValidThreshold(BYTE threshold, BYTE total);

private:
    static BYTE gfAdd(BYTE a, BYTE b);
    static BYTE gfSub(BYTE a, BYTE b);
    static BYTE gfMul(BYTE a, BYTE b);
    static BYTE gfDiv(BYTE a, BYTE b);
    static BYTE gfPow(BYTE base, int exp);
    static BYTE gfInv(BYTE a);
    static BYTE evalPoly(const std::vector<BYTE>& coeffs, BYTE x);
    static BYTE lagrangeConstant(const std::vector<std::pair<BYTE, BYTE>>& points);
};
