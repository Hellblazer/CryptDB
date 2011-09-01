#pragma once

#include <string>
#include <list>
#include <NTL/ZZ.h>

class Paillier;

class Paillier_privkey {
 public:
    Paillier_privkey(uint nbits = 1024, uint abits = 256);
    Paillier_privkey(const std::string &rep);
    std::string serialize();

 private:
    friend class Paillier;

    NTL::ZZ p, q, g;
    NTL::ZZ a;       /* non-zero for fast mode */
};

class Paillier {
 public:
    Paillier(const Paillier_privkey &k);
    NTL::ZZ encrypt(const NTL::ZZ &plaintext);
    NTL::ZZ decrypt(const NTL::ZZ &ciphertext);

    void rand_gen(size_t niter = 100, size_t nmax = 1000);
    NTL::ZZ pubkey(void) { return n2; }
    Paillier_privkey privkey(void) { return k; }

 private:
    Paillier_privkey k;

    uint nbits;
    bool fast;

    NTL::ZZ n;
    NTL::ZZ n2, p2, q2;
    NTL::ZZ two_p, two_q;
    NTL::ZZ pinv, qinv;
    NTL::ZZ hp, hq;

    std::list<NTL::ZZ> rqueue;
};
