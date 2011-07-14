#ifndef _OPE_H
#define _OPE_H

#include <stdio.h>
#include "util.h"

/*
 *
 * These functions implement OPE (order-preserving encryption).
 *
 * Optimization:
 * - batch encryption and decryption by temporarily storing assigned data
 * - first N intervals are generated using a PRG
 * - store in a tree for reuse
 */

class OPEInternals;

class OPE {
 public:
    /*
     * sizes are in bits
     * requires: key should have a number of bytes equal to OPE_KEY_SIZE
     */
    OPE(const string &key, unsigned int OPEPlaintextSize,
        unsigned int OPECiphertextSize);

    string encrypt(const string &plaintext);
    string decrypt(const string &ciphertext);

    uint64_t encrypt(uint32_t plaintext);
    uint32_t decrypt(uint64_t ciphertext);

 private:
    OPEInternals * iOPE;     //private methods and fields of OPE
};

#endif /* _OPE_H */
