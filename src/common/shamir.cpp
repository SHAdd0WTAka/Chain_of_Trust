#include "shamir.hpp"
#include <random>
#include <algorithm>

BYTE Shamir::gfAdd(BYTE a, BYTE b) {
    return a ^ b;
}

BYTE Shamir::gfSub(BYTE a, BYTE b) {
    return a ^ b;
}

BYTE Shamir::gfMul(BYTE a, BYTE b) {
    BYTE result = 0;
    BYTE carry;
    for (int i = 0; i < 8; i++) {
        if (b & 1) result ^= a;
        carry = a & 0x80;
        a <<= 1;
        if (carry) a ^= 0x1B;
        b >>= 1;
    }
    return result;
}

BYTE Shamir::gfDiv(BYTE a, BYTE b) {
    return gfMul(a, gfInv(b));
}

BYTE Shamir::gfPow(BYTE base, int exp) {
    if (exp == 0) return 1;
    BYTE result = base;
    for (int i = 1; i < exp; i++) {
        result = gfMul(result, base);
    }
    return result;
}

BYTE Shamir::gfInv(BYTE a) {
    if (a == 0) return 0;
    return gfPow(a, 254);
}

BYTE Shamir::evalPoly(const std::vector<BYTE>& coeffs, BYTE x) {
    BYTE result = 0;
    for (int i = (int)coeffs.size() - 1; i >= 0; i--) {
        result = gfMul(result, x) ^ coeffs[i];
    }
    return result;
}

BYTE Shamir::lagrangeConstant(const std::vector<std::pair<BYTE, BYTE>>& points) {
    BYTE result = 0;
    int n = (int)points.size();
    for (int i = 0; i < n; i++) {
        BYTE xi = points[i].first;
        BYTE yi = points[i].second;
        BYTE Li = 1;
        for (int j = 0; j < n; j++) {
            if (i == j) continue;
            BYTE xj = points[j].first;
            Li = gfMul(Li, xj);
            Li = gfMul(Li, gfInv(xi ^ xj));
        }
        result ^= gfMul(yi, Li);
    }
    return result;
}

bool Shamir::IsValidThreshold(BYTE threshold, BYTE total) {
    return threshold >= 2 && threshold <= total && total <= 255;
}

bool Shamir::Split(const std::vector<BYTE>& secret, BYTE threshold, BYTE total, std::vector<Shard>& outShards) {
    if (!IsValidThreshold(threshold, total) || secret.empty()) {
        return false;
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);

    outShards.resize(total);
    for (BYTE i = 0; i < total; i++) {
        outShards[i].ParticipantId = (BYTE)(i + 1);
        outShards[i].Data.resize(secret.size());
    }

    for (size_t byteIdx = 0; byteIdx < secret.size(); byteIdx++) {
        std::vector<BYTE> coeffs(threshold);
        coeffs[0] = secret[byteIdx];
        for (BYTE i = 1; i < threshold; i++) {
            coeffs[i] = (BYTE)dist(gen);
        }

        for (BYTE i = 0; i < total; i++) {
            outShards[i].Data[byteIdx] = evalPoly(coeffs, (BYTE)(i + 1));
        }
    }

    return true;
}

bool Shamir::Recover(const std::vector<Shard>& shards, BYTE threshold, std::vector<BYTE>& outSecret) {
    if ((BYTE)shards.size() < threshold || shards.empty() || threshold < 2) {
        return false;
    }

    size_t secretLen = shards[0].Data.size();
    if (secretLen == 0) return false;

    for (size_t i = 1; i < shards.size(); i++) {
        if (shards[i].Data.size() != secretLen) return false;
    }

    outSecret.resize(secretLen, 0);

    for (size_t byteIdx = 0; byteIdx < secretLen; byteIdx++) {
        std::vector<std::pair<BYTE, BYTE>> points;
        for (size_t s = 0; s < (size_t)threshold; s++) {
            points.push_back({ shards[s].ParticipantId, shards[s].Data[byteIdx] });
        }
        outSecret[byteIdx] = lagrangeConstant(points);
    }

    return true;
}
