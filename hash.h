// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECASHADDRCONV_HASH_H
#define ECASHADDRCONV_HASH_H

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <iostream>

/** A hasher class for SHA-256. */
class CSHA256 {
private:
    uint32_t s[8];
    uint8_t buf[64];
    uint64_t bytes;

public:
    static const size_t OUTPUT_SIZE = 32;

    CSHA256();
    CSHA256 &Write(const uint8_t *data, size_t len);
    void Finalize(uint8_t hash[OUTPUT_SIZE]);
    CSHA256 &Reset();
};

/** A hasher class for RIPEMD-160. */
class CRIPEMD160 {
private:
    uint32_t s[5];
    uint8_t buf[64];
    uint64_t bytes;

public:
    static const size_t OUTPUT_SIZE = 20;

    CRIPEMD160();
    CRIPEMD160 &Write(const uint8_t *data, size_t len);
    void Finalize(uint8_t hash[OUTPUT_SIZE]);
    CRIPEMD160 &Reset();
};

/** A hasher class for Bitcoin's 256-bit hash (double SHA-256). */
class CHash256 {
private:
    CSHA256 sha;

public:
    static const size_t OUTPUT_SIZE = CSHA256::OUTPUT_SIZE;

    void Finalize(std::vector<uint8_t> output) {
        assert(output.size() == OUTPUT_SIZE);
        uint8_t buf[CSHA256::OUTPUT_SIZE];
        sha.Finalize(buf);
        sha.Reset().Write(buf, CSHA256::OUTPUT_SIZE).Finalize(output.data());
    }

    CHash256 &Write(std::vector<uint8_t> input) {
        sha.Write(input.data(), input.size());
        return *this;
    }

    CHash256 &Reset() {
        sha.Reset();
        return *this;
    }
};

/** A hasher class for Bitcoin's 160-bit hash (SHA-256 + RIPEMD-160). */
class CHash160 {
private:
    CSHA256 sha;

public:
    static const size_t OUTPUT_SIZE = CRIPEMD160::OUTPUT_SIZE;

    void Finalize(std::vector<uint8_t> output) {
        assert(output.size() == OUTPUT_SIZE);
        uint8_t buf[CSHA256::OUTPUT_SIZE];
        sha.Finalize(buf);
        CRIPEMD160().Write(buf, CSHA256::OUTPUT_SIZE).Finalize(output.data());
    }

    CHash160 &Write(std::vector<uint8_t> input) {
        sha.Write(input.data(), input.size());
        return *this;
    }

    CHash160 &Reset() {
        sha.Reset();
        return *this;
    }
};

/** Compute the 256-bit hash of an object. */
inline std::vector<uint8_t> Hash(const std::vector<uint8_t> &in1) {
    std::vector<uint8_t> result(CSHA256::OUTPUT_SIZE, 0);
    CHash256().Write(in1).Finalize(result);
    return result;
}

/** Compute the 160-bit hash an object. */
inline std::vector<uint8_t> Hash160(const std::vector<uint8_t> &in1) {
    std::vector<uint8_t> result(CRIPEMD160::OUTPUT_SIZE, 0);
    CHash160().Write(in1).Finalize(result);
    return result;
}

namespace sha256 {

bool SelfTest();

} // namespace sha256

#endif //CASHADD_HASH_H
