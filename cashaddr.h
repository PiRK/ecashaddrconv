// Copyright (c) 2017 Pieter Wuille
// Copyright (c) 2017-2018 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CASHADDR_H
#define CASHADDR_H

// Cashaddr is an address format inspired by bech32.

#include <cstdint>
#include <initializer_list>
#include <map>
#include <string>
#include <type_traits>
#include <vector>

/** Concatenate two vectors. */
template <typename V> inline V Cat(V v1, const V &v2) {
    v1.reserve(v1.size() + v2.size());
    for (const auto &arg : v2) {
        v1.push_back(arg);
    }
    return v1;
}

/**
 * Convert from one power-of-2 number base to another.
 *
 * If padding is enabled, this always return true. If not, then it returns true
 * of all the bits of the input are encoded in the output.
 */
template <int frombits, int tobits, bool pad, typename O, typename I>
bool ConvertBits(const O &outfn, I it, I end) {
    size_t acc = 0;
    size_t bits = 0;
    constexpr size_t maxv = (1 << tobits) - 1;
    constexpr size_t max_acc = (1 << (frombits + tobits - 1)) - 1;
    while (it != end) {
        acc = ((acc << frombits) | *it) & max_acc;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            outfn((acc >> bits) & maxv);
        }
        ++it;
    }

    if (pad) {
        if (bits) {
            outfn((acc << (tobits - bits)) & maxv);
        }
    } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
        return false;
    }

    return true;
}

namespace cashaddr {

/**
* Encode a cashaddr string. Returns the empty string in case of failure.
*/
std::string Encode(const std::string &prefix,
                   const std::vector<uint8_t> &values);

/**
* Decode a cashaddr string. Returns (prefix, data). Empty prefix means failure.
*/
std::pair<std::string, std::vector<uint8_t>>
Decode(const std::string &str, const std::string &default_prefix);

}

const std::string MAINNET_PREFIX = "ecash";
const std::string TESTNET_PREFIX = "ectest";
const std::string REGTEST_PREFIX = "ecreg";
const std::string ETOKEN_PREFIX = "etoken";

enum AddrType : uint8_t { PUBKEY = 0, SCRIPT = 1 };
enum ChainType : uint8_t { MAIN = 0, TEST = 1, REG = 2 };

struct AddressContent {
    AddrType addressType;
    std::vector<uint8_t> hash;
    ChainType chainType {ChainType::MAIN};
};

std::string EncodeCashAddr(const std::string &prefix,
                           const AddressContent &content);

AddressContent DecodeCashAddrContent(const std::string &addr,
                                     const std::string &expectedPrefix);

std::string EncodeBase58(std::vector<uint8_t> input);

std::string EncodeBase58Check(std::vector<uint8_t> input);

bool DecodeBase58(const std::string &str, std::vector<uint8_t> &vch,
                  int max_ret_len);

bool DecodeBase58Check(const std::string &str, std::vector<uint8_t> &vchRet,
                       int max_ret_len);

std::string EncodeLegacyAddr(AddressContent content);

/**
 * Decode a legacy address, return true in case of success.
 *
 * Note that this function cannot discriminate testnet and regtest addresses,
 * as they are identical in legacy format. In both cases, content.ChainType
 * will be ChainType::TEST.
 *
 * @param str Legacy address
 * @param[out] outContent Address content.
 * @return
 */
bool DecodeLegacyAddr(const std::string &str, AddressContent &outContent);

#endif // CASHADDR_H
