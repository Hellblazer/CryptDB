#pragma once

#include <string>
#include <NTL/ZZ.h>

class OPE {
 public:
    OPE(const std::string &keyarg, size_t plainbits, size_t cipherbits)
        : key(keyarg), pbits(plainbits), cbits(cipherbits) {}
    NTL::ZZ encrypt(const NTL::ZZ &ptext);
    NTL::ZZ decrypt(const NTL::ZZ &ctext);

 private:
    std::string key;
    size_t pbits, cbits;
};
