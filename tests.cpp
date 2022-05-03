// Copyright (c) 2022 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "cashaddr.h"

#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>

#include <openssl/sha.h>

using namespace ecashaddr;

// convert string to back to lower case
static std::string to_lowercase(const std::string &str) {
    std::string ret;
    for(unsigned char c: str) {
        ret.push_back(std::tolower(c));
    }

    return ret;
}

static int char2int(char input) {
    if(input >= '0' && input <= '9') {
        return input - '0';
    }
    if(input >= 'A' && input <= 'F') {
        return input - 'A' + 10;
    }
    if(input >= 'a' && input <= 'f') {
        return input - 'a' + 10;
    }
    throw std::invalid_argument("Invalid input string");
}

// This function assumes hexstr to be a  sanitized string with
// an even number of [0-9a-f] characters
static std::vector<uint8_t> hex2bin(const std::string &hexstr) {
    std::vector<uint8_t> ret;
    size_t count = 0;
    uint8_t first_hex_digit;
    for (char const &c: hexstr) {
        if (count % 2) {
            ret.push_back(first_hex_digit + char2int(c));
        } else {
            first_hex_digit = char2int(c) << 4;
        }
        count++;
    }
    return ret;
}

static void assert_vectors_equal(const std::vector<uint8_t> vec1,
                            const std::vector<uint8_t> vec2) {
    assert(vec1.size() == vec2.size());
    for(size_t i = 0; i < vec1.size(); i ++ ) {
        assert(vec1[i] == vec2[i]);
    }
}

void hex2bin_tests() {
    assert(hex2bin("00") == std::vector<uint8_t>{0});
    assert(hex2bin("01") == std::vector<uint8_t>{1});
    assert(hex2bin("0a") == std::vector<uint8_t>{10});
    assert(hex2bin("0f") == std::vector<uint8_t>{15});
    assert(hex2bin("0F") == std::vector<uint8_t>{15});
    assert(hex2bin("FF") == std::vector<uint8_t>{255});
    assert_vectors_equal(hex2bin("010d"), std::vector<uint8_t>{1, 13});
    assert_vectors_equal(hex2bin("00011a0fFF"), std::vector<uint8_t>{0, 1, 26, 15, 255});
}

void cashaddr_testvectors_valid() {
    static const std::string CASES[] = {
        "prefix:x64nx6hz",
        "PREFIX:X64NX6HZ",
        "p:gpf8m4h7",
        "bitcoincash:qpzry9x8gf2tvdw0s3jn54khce6mua7lcw20ayyn",
        "bchtest:testnetaddress4d6njnut",
        "bchreg:555555555555555555555555555555555555555555555udxmlmrz",
    };

    for (const std::string &str : CASES) {
        auto [prefix, data] = cashaddr::Decode(str, "");
        assert(!prefix.empty());
        std::string recode = cashaddr::Encode(prefix, data);
        assert(!recode.empty());
        assert(to_lowercase(str) == recode);
    }
}

void cashaddr_testvectors_invalid() {
    static const std::string CASES[] = {
            "prefix:x32nx6hz",
            "prEfix:x64nx6hz",
            "prefix:x64nx6Hz",
            "pref1x:6m8cxv73",
            "prefix:",
            ":u9wsx07j",
            "bchreg:555555555555555555x55555555555555555555555555udxmlmrz",
            "bchreg:555555555555555555555555555555551555555555555udxmlmrz",
            "pre:fix:x32nx6hz",
            "prefixx64nx6hz",
    };

    for (const std::string &str : CASES) {
        auto [prefix, data] = cashaddr::Decode(str, "");
        assert(prefix.empty());
    }
}

void cashaddr_rawencode() {
    std::string prefix {"helloworld"};
    std::vector<uint8_t> payload = {0x1f, 0x0d};

    std::string encoded = cashaddr::Encode(prefix, payload);
    auto [decoded_prefix, decoded_payload] = cashaddr::Decode(encoded, "");

    assert(prefix == decoded_prefix);
    assert(payload == decoded_payload);
}

void cashaddr_testvectors_noprefix() {
    static const std::pair<std::string, std::string> CASES[] = {
        {"bitcoincash", "qpzry9x8gf2tvdw0s3jn54khce6mua7lcw20ayyn"},
        {"prefix", "x64nx6hz"},
        {"PREFIX", "X64NX6HZ"},
        {"p", "gpf8m4h7"},
        {"bitcoincash", "qpzry9x8gf2tvdw0s3jn54khce6mua7lcw20ayyn"},
        {"bchtest", "testnetaddress4d6njnut"},
        {"bchreg", "555555555555555555555555555555555555555555555udxmlmrz"},
    };

    for (const auto &[prefix, payload] : CASES) {
        std::string addr = prefix + ":" + payload;
        auto [decoded_prefix, decoded_payload] = cashaddr::Decode(payload, prefix);
        assert(decoded_prefix == prefix);
        std::string recode = cashaddr::Encode(decoded_prefix, decoded_payload);
        assert(!recode.empty());
        assert(to_lowercase(addr) == to_lowercase(recode));
    }
}

void base58_encode_decode() {
    // Encode
    assert(EncodeBase58({100}) == "2j");
    assert(EncodeBase58({0x27, 0x0f}) == "3yQ");
    std::vector<uint8_t> hello_world = {
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21};
    assert(EncodeBase58(hello_world) == "2NEpo7TZRRrLZSi2U");

    // Decode
    std::vector<uint8_t> vch;
    assert(DecodeBase58("2j", vch, 1000));
    assert(vch[0] == 100);

    vch.clear();
    assert(DecodeBase58("2NEpo7TZRRrLZSi2U", vch, 1000));
    assert_vectors_equal(vch, hello_world);

    // Illegal Base58 characters
    vch.clear();
    assert(!DecodeBase58("2NEpo7TZRRrLZSi2UiIL0O", vch, 1000));

    // Base58Check
    vch.clear();
    assert(DecodeBase58Check("1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i", vch, 21));
    // Expected 0065a16059864a2fdbc7c99a4723a8395bc6f188eb
    assert(vch[0] == 0 && vch[1] == 0x65 && vch[20] == 0xeb);

    vch.clear();
    assert(DecodeBase58Check("3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou", vch, 21));
    // Expected 0574f209f6ea907e2ea48f74fae05782ae8a665257
    assert(vch[0] == 5 && vch[1] == 0x74 && vch[20] == 0x57);

    vch.clear();
    assert(DecodeBase58Check("mo9ncXisMeAoXwqcV5EWuyncbmCcQN4rVs", vch, 21));
    // Expected 6f53c0307d6851aa0ce7825ba883c6bd9ad242b486
    assert(vch[0] == 0x6f && vch[1] == 0x53 && vch[20] == 0x86);

    vch.clear();
    assert(DecodeBase58Check("2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br", vch, 21));
    // Expected 6349a418fc4578d10a372b54b45c280cc8c4382f
    assert(vch[0] == 0xc4 && vch[1] == 0x63 && vch[20] == 0x2f);
}

void hash_testvectors() {
    // This is just to make sure I'm using the OpenSSL API correctly.
    // https://www.di-mgt.com.au/sha_testvectors.html
    std::vector<uint8_t> abc_vector{0x61, 0x62, 0x63};
    uint8_t hash1[32];
    SHA256((unsigned char*)abc_vector.data(), abc_vector.size(), (unsigned char*)&hash1);
    // expected ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    assert(hash1[0] == 0xba);
    assert(hash1[31] == 0xad);

    uint8_t abc_array[3]{0x61, 0x62, 0x63};
    uint8_t hash2[32];
    SHA256((unsigned char*)&abc_array, 3, (unsigned char*)&hash2);
    assert(hash2[0] == 0xba);
    assert(hash2[31] == 0xad);

    // Double sha256
    uint8_t hash3[32];
    SHA256((unsigned char*)&hash2, 32, (unsigned char*)&hash3);
    // expected 4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358
    assert(hash3[0] == 0x4f);
    assert(hash3[31] == 0x58);
}

void decode_encode_address_content() {
    std::vector<std::tuple<std::string, std::string, AddressContent>> vectors = {
        {
            "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i",
            "ecash:qpj6zczese9zlk78exdywgag89duduvgavmld27rw2",
            {
                AddressType::PUBKEY,
                hex2bin("65a16059864a2fdbc7c99a4723a8395bc6f188eb"),
                ChainType::MAIN
            }
        },
        {
            "3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou",
            "ecash:pp60yz0ka2g8ut4y3a604czhs2hg5ejj2u37npfnk5",
            {
                AddressType::SCRIPT,
                hex2bin("74f209f6ea907e2ea48f74fae05782ae8a665257"),
                ChainType::MAIN
            }
        },
        {
            "mo9ncXisMeAoXwqcV5EWuyncbmCcQN4rVs",
            "ectest:qpfuqvradpg65r88sfd63q7xhkddys45scc07d7pk5",
            {
                AddressType::PUBKEY,
                hex2bin("53c0307d6851aa0ce7825ba883c6bd9ad242b486"),
                ChainType::TEST
            }
        },
        {
            "2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br",
            "ectest:pp35nfqcl3zh35g2xu44fdzu9qxv33pc9u2q0rkcs9",
            {
                AddressType::SCRIPT,
                hex2bin("6349a418fc4578d10a372b54b45c280cc8c4382f"),
                ChainType::TEST
            }
        },
        {
            "mo9ncXisMeAoXwqcV5EWuyncbmCcQN4rVs",
            "ecreg:qpfuqvradpg65r88sfd63q7xhkddys45scr94988sn",
            {
                AddressType::PUBKEY,
                hex2bin("53c0307d6851aa0ce7825ba883c6bd9ad242b486"),
                ChainType::REG
            }
        },
        {
            "2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br",
            "ecreg:pp35nfqcl3zh35g2xu44fdzu9qxv33pc9u32yt07kz",
            {
                AddressType::SCRIPT,
                hex2bin("6349a418fc4578d10a372b54b45c280cc8c4382f"),
                ChainType::REG
            }
        }
    };

    for(auto [legacyAddr, cashAddr, content]: vectors) {
        // legacy
        assert(EncodeLegacyAddress(content) == legacyAddr);

        AddressContent decodedContent;
        assert(DecodeLegacyAddress(legacyAddr, decodedContent));
        assert(decodedContent.addressType == content.addressType);
        if (content.chainType != decodedContent.chainType) {
            // The legacy format does not discriminate testnet and regtest
            // addresses, so DecodeLegacyAddress returns ChainType::TEST.
            assert(content.chainType == ChainType::REG &&
                   decodedContent.chainType == ChainType::TEST);
        }
        assert_vectors_equal(decodedContent.hash, content.hash);

        // cash address
        std::string expected_prefix = PrefixFromChainType(content.chainType);

        assert(EncodeCashAddress(expected_prefix, content) == cashAddr);
        AddressContent decodedContent2;
        assert(DecodeCashAddress(cashAddr, expected_prefix, decodedContent2));
        assert(decodedContent2.chainType == content.chainType);
        assert(decodedContent2.addressType == content.addressType);
        assert_vectors_equal(decodedContent2.hash, content.hash);

        // direct conversion (REGTEST excluded because legacy regtest addresses
        // cannot be differentiated from legacy testnet addresses)
        if (content.chainType != ChainType::REG) {
            assert(Legacy2CashAddress(legacyAddr) == cashAddr);
        }
        assert(CashAddress2Legacy(cashAddr, expected_prefix) == legacyAddr);
    }
}

void convert_cashaddr_to_legacy() {
    std::string addr1 = "qpelrdn7a0hcucjlf9ascz3lkxv7r3rffgzn6x5377";
    std::string prefixed_addr1 = MAINNET_PREFIX + ":" + addr1;

    for (auto addr: {addr1, prefixed_addr1}) {
        auto[prefix, payload] = cashaddr::Decode(addr, MAINNET_PREFIX);
        auto recode = cashaddr::Encode(prefix, payload);
        assert(recode == prefixed_addr1);

        AddressContent content;
        assert(DecodeCashAddress(addr, MAINNET_PREFIX, content));
        std::string recode2 = EncodeCashAddress(MAINNET_PREFIX, content);
        assert(recode2 == prefixed_addr1);

        std::string legacy = EncodeLegacyAddress(content);
        assert(legacy == "1Ba4GZo5pnYJvNNXTi3FEKcYJ8AHkiu9ni");

        assert(Legacy2CashAddress(legacy) == prefixed_addr1);
        assert(CashAddress2Legacy(addr, MAINNET_PREFIX) == legacy);
    }


}

int main(int argc, char** argv) {
    hex2bin_tests();
    cashaddr_testvectors_valid();
    cashaddr_testvectors_invalid();
    cashaddr_rawencode();
    cashaddr_testvectors_noprefix();
    base58_encode_decode();
    hash_testvectors();
    decode_encode_address_content();
    convert_cashaddr_to_legacy();

    std::cout << "Test suite completed successfully." << std::endl;
    return 0;
}
