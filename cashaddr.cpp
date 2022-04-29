// Copyright (c) 2017 Pieter Wuille
// Copyright (c) 2017-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "cashaddr.h"

#include <cassert>
#include <iostream>
#include <openssl/sha.h>
#include <stdexcept>

/**
 * The cashaddr character set for encoding.
 */
const char *CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/**
 * The cashaddr character set for decoding.
 */
const int8_t CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 15, -1, 10, 17, 21, 20, 26, 30, 7,
    5,  -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9,  8,  23, -1, 18, 22,
    31, 27, 19, -1, 1,  0,  3,  16, 11, 28, 12, 14, 6,  4,  2,  -1, -1, -1, -1,
    -1, -1, 29, -1, 24, 13, 25, 9,  8,  23, -1, 18, 22, 31, 27, 19, -1, 1,  0,
    3,  16, 11, 28, 12, 14, 6,  4,  2,  -1, -1, -1, -1, -1};

/**
 * This function will compute what 8 5-bit values to XOR into the last 8 input
 * values, in order to make the checksum 0. These 8 values are packed together
 * in a single 40-bit integer. The higher bits correspond to earlier values.
 */
uint64_t PolyMod(const std::vector<uint8_t> &v) {
    /**
     * The input is interpreted as a list of coefficients of a polynomial over F
     * = GF(32), with an implicit 1 in front. If the input is [v0,v1,v2,v3,v4],
     * that polynomial is v(x) = 1*x^5 + v0*x^4 + v1*x^3 + v2*x^2 + v3*x + v4.
     * The implicit 1 guarantees that [v0,v1,v2,...] has a distinct checksum
     * from [0,v0,v1,v2,...].
     *
     * The output is a 40-bit integer whose 5-bit groups are the coefficients of
     * the remainder of v(x) mod g(x), where g(x) is the cashaddr generator, x^8
     * + {19}*x^7 + {3}*x^6 + {25}*x^5 + {11}*x^4 + {25}*x^3 + {3}*x^2 + {19}*x
     * + {1}. g(x) is chosen in such a way that the resulting code is a BCH
     * code, guaranteeing detection of up to 4 errors within a window of 1025
     * characters. Among the various possible BCH codes, one was selected to in
     * fact guarantee detection of up to 5 errors within a window of 160
     * characters and 6 erros within a window of 126 characters. In addition,
     * the code guarantee the detection of a burst of up to 8 errors.
     *
     * Note that the coefficients are elements of GF(32), here represented as
     * decimal numbers between {}. In this finite field, addition is just XOR of
     * the corresponding numbers. For example, {27} + {13} = {27 ^ 13} = {22}.
     * Multiplication is more complicated, and requires treating the bits of
     * values themselves as coefficients of a polynomial over a smaller field,
     * GF(2), and multiplying those polynomials mod a^5 + a^3 + 1. For example,
     * {5} * {26} = (a^2 + 1) * (a^4 + a^3 + a) = (a^4 + a^3 + a) * a^2 + (a^4 +
     * a^3 + a) = a^6 + a^5 + a^4 + a = a^3 + 1 (mod a^5 + a^3 + 1) = {9}.
     *
     * During the course of the loop below, `c` contains the bitpacked
     * coefficients of the polynomial constructed from just the values of v that
     * were processed so far, mod g(x). In the above example, `c` initially
     * corresponds to 1 mod (x), and after processing 2 inputs of v, it
     * corresponds to x^2 + v0*x + v1 mod g(x). As 1 mod g(x) = 1, that is the
     * starting value for `c`.
     */
    uint64_t c = 1;
    for (uint8_t d : v) {
        /**
         * We want to update `c` to correspond to a polynomial with one extra
         * term. If the initial value of `c` consists of the coefficients of
         * c(x) = f(x) mod g(x), we modify it to correspond to
         * c'(x) = (f(x) * x + d) mod g(x), where d is the next input to
         * process.
         *
         * Simplifying:
         * c'(x) = (f(x) * x + d) mod g(x)
         *         ((f(x) mod g(x)) * x + d) mod g(x)
         *         (c(x) * x + d) mod g(x)
         * If c(x) = c0*x^5 + c1*x^4 + c2*x^3 + c3*x^2 + c4*x + c5, we want to
         * compute
         * c'(x) = (c0*x^5 + c1*x^4 + c2*x^3 + c3*x^2 + c4*x + c5) * x + d
         *                                                             mod g(x)
         *       = c0*x^6 + c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 + c5*x + d
         *                                                             mod g(x)
         *       = c0*(x^6 mod g(x)) + c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 +
         *                                                             c5*x + d
         * If we call (x^6 mod g(x)) = k(x), this can be written as
         * c'(x) = (c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 + c5*x + d) + c0*k(x)
         */

        // First, determine the value of c0:
        uint8_t c0 = c >> 35;

        // Then compute c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 + c5*x + d:
        c = ((c & 0x07ffffffff) << 5) ^ d;

        // Finally, for each set bit n in c0, conditionally add {2^n}k(x):
        if (c0 & 0x01) {
            // k(x) = {19}*x^7 + {3}*x^6 + {25}*x^5 + {11}*x^4 + {25}*x^3 +
            //        {3}*x^2 + {19}*x + {1}
            c ^= 0x98f2bc8e61;
        }

        if (c0 & 0x02) {
            // {2}k(x) = {15}*x^7 + {6}*x^6 + {27}*x^5 + {22}*x^4 + {27}*x^3 +
            //           {6}*x^2 + {15}*x + {2}
            c ^= 0x79b76d99e2;
        }

        if (c0 & 0x04) {
            // {4}k(x) = {30}*x^7 + {12}*x^6 + {31}*x^5 + {5}*x^4 + {31}*x^3 +
            //           {12}*x^2 + {30}*x + {4}
            c ^= 0xf33e5fb3c4;
        }

        if (c0 & 0x08) {
            // {8}k(x) = {21}*x^7 + {24}*x^6 + {23}*x^5 + {10}*x^4 + {23}*x^3 +
            //           {24}*x^2 + {21}*x + {8}
            c ^= 0xae2eabe2a8;
        }

        if (c0 & 0x10) {
            // {16}k(x) = {3}*x^7 + {25}*x^6 + {7}*x^5 + {20}*x^4 + {7}*x^3 +
            //            {25}*x^2 + {3}*x + {16}
            c ^= 0x1e4f43e470;
        }
    }

    /**
     * PolyMod computes what value to xor into the final values to make the
     * checksum 0. However, if we required that the checksum was 0, it would be
     * the case that appending a 0 to a valid list of values would result in a
     * new valid list. For that reason, cashaddr requires the resulting checksum
     * to be 1 instead.
     */
    return c ^ 1;
}

/**
 * Convert to lower case.
 *
 * Assume the input is a character.
 */
inline uint8_t LowerCase(uint8_t c) {
    // ASCII black magic.
    return c | 0x20;
}

/**
 * Expand the address prefix for the checksum computation.
 */
std::vector<uint8_t> ExpandPrefix(const std::string &prefix) {
    std::vector<uint8_t> ret;
    ret.resize(prefix.size() + 1);
    for (size_t i = 0; i < prefix.size(); ++i) {
        ret[i] = prefix[i] & 0x1f;
    }

    ret[prefix.size()] = 0;
    return ret;
}

/**
 * Verify a checksum.
 */
bool VerifyChecksum(const std::string &prefix, const std::vector<uint8_t> &payload) {
    return PolyMod(Cat(ExpandPrefix(prefix), payload)) == 0;
}

/**
 * Create a checksum.
 */
std::vector<uint8_t> CreateChecksum(const std::string &prefix, const std::vector<uint8_t> &payload) {
    std::vector<uint8_t> enc = Cat(ExpandPrefix(prefix), payload);
    // Append 8 zeroes.
    enc.resize(enc.size() + 8);
    // Determine what to XOR into those 8 zeroes.
    uint64_t mod = PolyMod(enc);
    std::vector<uint8_t> ret(8);
    for (size_t i = 0; i < 8; ++i) {
        // Convert the 5-bit groups in mod to checksum values.
        ret[i] = (mod >> (5 * (7 - i))) & 0x1f;
    }

    return ret;
}

namespace cashaddr {
/**
* Encode a cashaddr string.
*/
std::string Encode(const std::string &prefix, const std::vector<uint8_t> &payload) {
    std::vector<uint8_t> checksum = CreateChecksum(prefix, payload);
    std::vector<uint8_t> combined = Cat(payload, checksum);
    // This is a deviation from Bitcoin ABC. We want the output
    std::string ret = prefix + ':';

    ret.reserve(ret.size() + combined.size());
    for (uint8_t c: combined) {
        ret += CHARSET[c];
    }

    return ret;
}

/**
* Decode a cashaddr string.
*/
std::pair<std::string, std::vector<uint8_t>> Decode(const std::string &str,
                                    const std::string &default_prefix) {
    // Go over the string and do some sanity checks.
    bool lower = false, upper = false, hasNumber = false;
    size_t prefixSize = 0;
    for (size_t i = 0; i < str.size(); ++i) {
        uint8_t c = str[i];
        if (c >= 'a' && c <= 'z') {
            lower = true;
            continue;
        }

        if (c >= 'A' && c <= 'Z') {
            upper = true;
            continue;
        }

        if (c >= '0' && c <= '9') {
            // We cannot have numbers in the prefix.
            hasNumber = true;
            continue;
        }

        if (c == ':') {
            // The separator cannot be the first character, cannot have number
            // and there must not be 2 separators.
            if (hasNumber || i == 0 || prefixSize != 0) {
                return {};
            }

            prefixSize = i;
            continue;
        }

        // We have an unexpected character.
        return {};
    }

    // We can't have both upper case and lowercase.
    if (upper && lower) {
        return {};
    }

    // Get the prefix.
    std::string prefix;
    if (prefixSize == 0) {
        prefix = default_prefix;
    } else {
        prefix.reserve(prefixSize);
        for (size_t i = 0; i < prefixSize; ++i) {
            prefix += LowerCase(str[i]);
        }

        // Now add the ':' in the size.
        prefixSize++;
    }

    // Decode values.
    const size_t valuesSize = str.size() - prefixSize;
    std::vector<uint8_t> values(valuesSize);
    for (size_t i = 0; i < valuesSize; ++i) {
        uint8_t c = str[i + prefixSize];
        // We have an invalid char in there.
        if (c > 127 || CHARSET_REV[c] == -1) {
            return {};
        }

        values[i] = CHARSET_REV[c];
    }

    // Verify the checksum.
    if (!VerifyChecksum(prefix, values)) {
        return {};
    }

    return {std::move(prefix), std::vector<uint8_t>(values.begin(), values.end() - 8)};
}
}

// Convert the data part to a 5 bit representation.
std::vector<uint8_t> PackAddrData(const std::vector<uint8_t> &hash, uint8_t type) {
    uint8_t version_byte(type << 3);
    size_t size = hash.size();
    uint8_t encoded_size = 0;
    switch (size * 8) {
        case 160:
            encoded_size = 0;
            break;
        case 192:
            encoded_size = 1;
            break;
        case 224:
            encoded_size = 2;
            break;
        case 256:
            encoded_size = 3;
            break;
        case 320:
            encoded_size = 4;
            break;
        case 384:
            encoded_size = 5;
            break;
        case 448:
            encoded_size = 6;
            break;
        case 512:
            encoded_size = 7;
            break;
        default:
            throw std::runtime_error(
                "Error packing cashaddr: invalid address length");
    }
    version_byte |= encoded_size;
    std::vector<uint8_t> data = {version_byte};
    data.insert(data.end(), std::begin(hash), std::end(hash));

    std::vector<uint8_t> converted;
    // Reserve the number of bytes required for a 5-bit packed version of a
    // hash, with version byte.  Add half a byte(4) so integer math provides
    // the next multiple-of-5 that would fit all the data.
    converted.reserve(((size + 1) * 8 + 4) / 5);
    ConvertBits<8, 5, true>([&](uint8_t c) { converted.push_back(c); },
                            std::begin(data), std::end(data));

    return converted;
}

std::string EncodeCashAddr(const std::string &prefix,
                           const CashAddrContent &content) {
    std::vector<uint8_t> data = PackAddrData(content.hash, content.type);
    return cashaddr::Encode(prefix, data);
}

CashAddrContent DecodeCashAddrContent(const std::string &addr,
                                      const std::string &expectedPrefix) {
    auto [prefix, payload] = cashaddr::Decode(addr, expectedPrefix);

    if (prefix != expectedPrefix) {
        return {};
    }

    if (payload.empty()) {
        return {};
    }

    std::vector<uint8_t> data;
    data.reserve(payload.size() * 5 / 8);
    if (!ConvertBits<5, 8, false>([&](uint8_t c) { data.push_back(c); },
                                  begin(payload), end(payload))) {
        return {};
    }

    // Decode type and size from the version.
    uint8_t version = data[0];
    if (version & 0x80) {
        // First bit is reserved.
        return {};
    }

    auto type = AddrType((version >> 3) & 0x1f);
    uint32_t hash_size = 20 + 4 * (version & 0x03);
    if (version & 0x04) {
        hash_size *= 2;
    }

    // Check that we decoded the exact number of bytes we expected.
    if (data.size() != hash_size + 1) {
        return {};
    }

    // Pop the version.
    data.erase(data.begin());
    return {type, std::move(data)};
}

/** All alphanumeric characters except for "0", "I", "O", and "l" */
static const char *pszBase58 =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string EncodeBase58(std::vector<uint8_t> input) {
    // Skip & count leading zeroes.
    int zeroes = 0;
    int length = 0;
    while (input.size() > 0 && input[0] == 0) {
        input.erase(input.begin());
        zeroes++;
    }
    // Allocate enough space in big-endian base58 representation.
    // log(256) / log(58), rounded up.
    int size = input.size() * 138 / 100 + 1;
    std::vector<uint8_t> b58(size);
    // Process the bytes.
    while (input.size() > 0) {
        int carry = input[0];
        int i = 0;
        // Apply "b58 = b58 * 256 + ch".
        for (std::vector<uint8_t>::reverse_iterator it = b58.rbegin();
             (carry != 0 || i < length) && (it != b58.rend()); it++, i++) {
            carry += 256 * (*it);
            *it = carry % 58;
            carry /= 58;
        }

        assert(carry == 0);
        length = i;
        input.erase(input.begin());
    }
    // Skip leading zeroes in base58 result.
    std::vector<uint8_t>::iterator it = b58.begin() + (size - length);
    while (it != b58.end() && *it == 0) {
        it++;
    }
    // Translate the result into a string.
    std::string str;
    str.reserve(zeroes + (b58.end() - it));
    str.assign(zeroes, '1');
    while (it != b58.end()) {
        str += pszBase58[*(it++)];
    }
    return str;
}

std::string EncodeBase58Check(std::vector<uint8_t> input) {
    // add 4-byte hash check to the end
    std::vector<uint8_t> vch(input.begin(), input.end());
    assert(vch.size() == input.size());

    uint8_t hash1[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)vch.data(), vch.size(), (unsigned char*)&hash1);
    uint8_t hash2[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)&hash1, SHA256_DIGEST_LENGTH, (unsigned char*)&hash2);

    vch.insert(vch.end(), (uint8_t *)&hash2, (uint8_t *)&hash2 + 4);
    return EncodeBase58(vch);
}

std::map<uint8_t , std::map<uint8_t , std::vector<uint8_t>>> base58Prefixes = {
    {ChainType::MAIN, {{AddrType::PUBKEY, std::vector<uint8_t>(1, 0)}}},
    {ChainType::MAIN, {{AddrType::SCRIPT, std::vector<uint8_t>(1, 5)}}},
    {ChainType::TEST, {{AddrType::PUBKEY, std::vector<uint8_t>(1, 111)}}},
    {ChainType::TEST, {{AddrType::SCRIPT, std::vector<uint8_t>(1, 196)}}},
    {ChainType::REG, {{AddrType::PUBKEY, std::vector<uint8_t>(1, 111)}}},
    {ChainType::REG, {{AddrType::SCRIPT, std::vector<uint8_t>(1, 196)}}},
};

std::string EncodeLegacyAddr(CashAddrContent content) {
//    std::vector<uint8_t> data = base58Prefixes[content.chainType][content.type];
    std::vector <uint8_t> data;
    if (content.chainType == ChainType::MAIN) {
        if (content.type == AddrType::PUBKEY) {
            data.push_back(0);
        } else {
            data.push_back(5);
        }
    } else {
        // REGTEST or TESTNET
        if (content.type == AddrType::PUBKEY) {
            data.push_back(111);
        } else {
            data.push_back(196);
        }
    }
    data.insert(data.end(), content.hash.begin(), content.hash.end());
    return EncodeBase58Check(data);
}
