// Copyright (c) 2017 Pieter Wuille
// Copyright (c) 2017-2022 The Bitcoin developers
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

namespace {

/** Concatenate two vectors. */
template<typename V>
inline V Cat(V v1, const V &v2) {
    v1.reserve(v1.size() + v2.size());
    for (const auto &arg: v2) {
        v1.push_back(arg);
    }
    return v1;
}

/**
* Convert from one power-of-2 number base to another.
*
* If padding is enabled, this always return true. If not, then it returns true
* if all the bits of the input are encoded in the output.
*/
template<int frombits, int tobits, bool pad, typename O, typename I>
bool ConvertBits(const O &outfn, I it, I end) {
    size_t acc = 0;
    size_t bits = 0;
    constexpr
    size_t maxv = (1 << tobits) - 1;
    constexpr
    size_t max_acc = (1 << (frombits + tobits - 1)) - 1;
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

}  // namespace

////////////////
// Public API

namespace ecashaddr {

const std::string MAINNET_PREFIX = "ecash";
const std::string TESTNET_PREFIX = "ectest";
const std::string REGTEST_PREFIX = "ecreg";

enum AddressType : uint8_t {
    PUBKEY = 0, SCRIPT = 1
};

enum ChainType : uint8_t {
    MAIN = 0, TEST = 1, REG = 2, UNKNOWN = 3
};

struct AddressContent {
    AddressType addressType;
    std::vector <uint8_t> hash;
    ChainType chainType{ChainType::MAIN};
};

/**
* Encode a cash address from a payload (hash).
*
* @param prefix Cash address prefix to be used in the output address.
* @param content AddressContent provides the payload (script hash or public key
*                hash) and chain parameters (main chain, testnet, or regtest).
* @return cash address
*/
std::string EncodeCashAddress(const std::string &prefix,
                              const AddressContent &content);

/**
* Decode a cash address.
*
* The chainType is deduced from the prefix. If the prefix is not one of
* "ecash", "ectest", or "ecreg", outContent.chainType will be set to
* ChainType::UNKNOWN.
*
* @param address Cash address, with or without prefix.
* @param expectedPrefix Expected prefix. This is used to verify the checksum
*                       part of the address.
* @param[out] outContent Address content.
* @return true in case of success.
*/
bool DecodeCashAddress(const std::string &address,
                       const std::string &expectedPrefix,
                       AddressContent &outContent);

/**
* Encode a legacy address from a payload (hash).
*
* @param content AddressContent provides the payload (script hash or public key
*                hash) and chain parameters.
* @return cash address
*/
std::string EncodeLegacyAddress(AddressContent content);

/**
* Decode a legacy address.
*
* Note that this function cannot discriminate testnet and regtest addresses,
* as they are identical in legacy format. In both cases, content.ChainType
* will be ChainType::TEST.
*
* @param str Legacy address
* @param[out] outContent Address content.
* @return true in case of success.
*/
bool DecodeLegacyAddress(const std::string &str, AddressContent &outContent);


/**
* Convert a legacy address to a CashAddress.
*
* The prefix "ecash:" or "ectest:" is determined from the address version byte.
*
* @param legacyAddr Legacy address.
* @return Cash address or empty string in case of failure
*/
std::string Legacy2CashAddress(const std::string &legacyAddr);

/**
* Convert a cash address to a legacy address.
*
* @param cashAddr  Cash address. The prefix can be specified or omitted.
* @param expectedPrefix Specify the expected prefix. This is used to verify the
*                       checksum suffix of the address.
*                       This parameter can be omitted when working only with
*                       main net "ecash:" addresses.
* @return Legacy address or empty string in case of failure
*/
// TODO: make expectedPrefix really optional when the address has it and it is
//       correct. For now, not specifying it only works for mainnet.
std::string CashAddress2Legacy(const std::string &cashAddr,
                               const std::string &expectedPrefix = MAINNET_PREFIX);

////////////////////////////////////////
// Functions made public for unit tests

namespace cashaddr {

/**
* Encode a cashaddr string. Returns the empty string in case of failure.
*/
std::string Encode(const std::string &prefix,
                   const std::vector <uint8_t> &values);

/**
* Decode a cashaddr string. Returns (prefix, data). Empty prefix means failure.
*/
std::pair <std::string, std::vector<uint8_t>>
Decode(const std::string &str, const std::string &default_prefix);

}  // namespace cashaddr


std::string EncodeBase58(std::vector <uint8_t> input);

std::string EncodeBase58Check(std::vector <uint8_t> input);

bool DecodeBase58(const std::string &str, std::vector <uint8_t> &vch,
                  int max_ret_len);

bool DecodeBase58Check(const std::string &str, std::vector <uint8_t> &vchRet,
                       int max_ret_len);

std::string PrefixFromChainType(const ChainType &chainType);

}  // namespace ecashaddr

#endif // CASHADDR_H
