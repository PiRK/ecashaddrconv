// Copyright (c) 2022 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "cashaddr.h"
#include <iostream>

// Helper functions

/** Convert an hexadecimal digit to an integer */
static int char2int(char hexChar) {
    if(hexChar >= '0' && hexChar <= '9') {
        return hexChar - '0';
    }
    if(hexChar >= 'A' && hexChar <= 'F') {
        return hexChar - 'A' + 10;
    }
    if(hexChar >= 'a' && hexChar <= 'f') {
        return hexChar - 'a' + 10;
    }
    throw std::invalid_argument("Invalid input char");
}

/** Convert a hexadecimal string to a vector of bytes (uint8_t) */
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


int main(int argc, char** argv) {
    std::string legacy_address1 = "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i";
    std::string cash_address1 = Legacy2CashAddr(legacy_address1);

    std::cout << "Legacy address: " << legacy_address1 << "\nCash address: "
              << cash_address1 << std::endl;
    std::cout << std::endl;

    std::string expected_prefix2 = "ectest";
    std::string cash_address2 = "qpfuqvradpg65r88sfd63q7xhkddys45scc07d7pk5";
    std::string legacy_address2 = CashAddr2Legacy(cash_address2, expected_prefix2);
    std::cout << "Testnet cash address: " << cash_address2
              << "\nLegacy address: " << legacy_address2 << std::endl;
    std::cout << std::endl;

    // The expected prefix can be omitted for main chain addresses
    // (prefix "ecash")
    std::cout << "Cash address: "
              << CashAddr2Legacy("pp60yz0ka2g8ut4y3a604czhs2hg5ejj2u37npfnk5")
              << std::endl;
    std::cout << std::endl;

    // The cashaddr can be specified with or without the prefix
    std::cout << "Cash address: "
              << CashAddr2Legacy("ecreg:qpfuqvradpg65r88sfd63q7xhkddys45scr94988sn", "ecreg")
              << std::endl;
    std::cout << "Cash address: "
              << CashAddr2Legacy("qpfuqvradpg65r88sfd63q7xhkddys45scr94988sn", "ecreg")
              << std::endl;
    std::cout << std::endl;

    // Encode an address from a public key hash or script hash
    AddressContent address_content {
        AddrType::PUBKEY,
        hex2bin("65a16059864a2fdbc7c99a4723a8395bc6f188eb"),
        ChainType::MAIN};
    std::cout << "Legacy address: " << EncodeLegacyAddr(address_content)
              << std::endl;
    std::cout << "Cash address: "  << EncodeCashAddr("ecash", address_content)
              << std::endl;
}
