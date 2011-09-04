#pragma once

#include <string>
#include <NTL/ZZ.h>

class OPE {
 public:
    OPE(const std::string &keyarg, size_t plainbits, size_t cipherbits)
        : key(keyarg), pbits(plainbits), cbits(cipherbits) {}

    /*
     * Randomized OPE.
     *
     * Return an encryption of ptext, if offset = 0.
     * Return an encryption between E(ptext-1) and E(ptext) if offset = -1.
     * Return an encryption between E(ptext) and E(ptext+1) if offset = 1.
     */
    NTL::ZZ encrypt(const NTL::ZZ &ptext, int offset = 0);
    NTL::ZZ decrypt(const NTL::ZZ &ctext);

 private:
    std::string key;
    size_t pbits, cbits;
};
