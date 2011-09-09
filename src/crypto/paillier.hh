#pragma once

#include <list>
#include <vector>
#include <NTL/ZZ.h>

class Paillier {
 public:
    Paillier(const std::vector<NTL::ZZ> &pk);
    std::vector<NTL::ZZ> pubkey() const { return { n, g }; }

    NTL::ZZ encrypt(const NTL::ZZ &plaintext);
    NTL::ZZ add(const NTL::ZZ &c0, const NTL::ZZ &c1) const;

    void rand_gen(size_t niter = 100, size_t nmax = 1000);

 protected:
    /* Public key */
    NTL::ZZ n, g;

    /* Cached values */
    uint nbits;
    NTL::ZZ n2;

    /* Pre-computed randomness */
    std::list<NTL::ZZ> rqueue;
};

class Paillier_priv : public Paillier {
 public:
    Paillier_priv(const std::vector<NTL::ZZ> &sk);
    std::vector<NTL::ZZ> privkey() const { return { p, q, g, a }; }

    NTL::ZZ decrypt(const NTL::ZZ &ciphertext) const;

    static std::vector<NTL::ZZ> keygen(uint nbits = 1024, uint abits = 256);

 private:
    /* Private key, including g from public part; n=pq */
    NTL::ZZ p, q;
    NTL::ZZ a;      /* non-zero for fast mode */

    /* Cached values */
    bool fast;
    NTL::ZZ p2, q2;
    NTL::ZZ two_p, two_q;
    NTL::ZZ pinv, qinv;
    NTL::ZZ hp, hq;
};
