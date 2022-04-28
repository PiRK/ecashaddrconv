#include "cashaddr.h"
#include <cassert>
#include <iostream>

// convert string to back to lower case
static std::string to_lowercase(const std::string &str) {
    std::string ret;
    for(unsigned char c: str) {
        ret.push_back(std::tolower(c));
    }

    return ret;
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

int main(int argc, char** argv) {
    cashaddr_testvectors_valid();
    cashaddr_testvectors_invalid();
    cashaddr_rawencode();
    cashaddr_testvectors_noprefix();

    std::cout << "Test suite completed successfully." << std::endl;
    return 0;
}
