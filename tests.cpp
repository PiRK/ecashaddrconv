#include "cashaddr.h"
#include "hash.h"

#include <cassert>
#include <cstring>
#include <iostream>

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

void base58_encode() {
    assert(EncodeBase58({100}) == "2j");
    assert(EncodeBase58({0x27, 0x0f}) == "3yQ");
    std::vector<uint8_t> hello_world = {
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21};
    assert(EncodeBase58(hello_world) == "2NEpo7TZRRrLZSi2U");
}

//void encode_legacy_address() {
//    CashAddrContent content{
//        AddrType::PUBKEY,
//        hex2bin("eb88f1c65b39a823479ac9c7db2f4a865960a165"),
//        ChainType::MAIN
//    };
//    std::cout << EncodeLegacyAddr(content) << std::endl;
//    assert(EncodeLegacyAddr(content) == "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i");
//}

void convert_cashaddr_to_legacy() {
    std::string addr1 = "qpelrdn7a0hcucjlf9ascz3lkxv7r3rffgzn6x5377";
    std::string prefixed_addr1 = MAINNET_PREFIX + ":" + addr1;

    for (auto addr: {addr1, prefixed_addr1}) {
        auto[prefix, payload] = cashaddr::Decode(addr, MAINNET_PREFIX);
        auto recode = cashaddr::Encode(prefix, payload);
        assert(recode == prefixed_addr1);

        CashAddrContent content = DecodeCashAddrContent(addr, MAINNET_PREFIX);
        std::string recode2 = EncodeCashAddr(MAINNET_PREFIX, content);
        assert(recode2 == prefixed_addr1);

        std::string legacy = EncodeLegacyAddr(content);
        std::cout << legacy << std::endl;
        // FIXME: expected 1Ba4GZo5pnYJvNNXTi3FEKcYJ8AHkiu9ni
        //        actual: good payload but wrong (random) checksum
    }
}

void hash_test() {
    assert(sha256::SelfTest());
}

int main(int argc, char** argv) {
    hex2bin_tests();
    cashaddr_testvectors_valid();
    cashaddr_testvectors_invalid();
    cashaddr_rawencode();
    cashaddr_testvectors_noprefix();
    base58_encode();
    hash_test();
//    encode_legacy_address();
    convert_cashaddr_to_legacy();

    std::cout << "Test suite completed successfully." << std::endl;
    return 0;
}
