#pragma once

#include <string.h>
#include <string>
#include <vector>
#include <fstream>
#include <util/errstream.hh>
#include <NTL/ZZ.h>

class PRNG {
 public:
    template<class T>
    T rand() {
        T v;
        rand_bytes(sizeof(T), (uint8_t*) &v);
        return v;
    }

    std::string rand_string(size_t nbytes) {
        std::string s;
        s.resize(nbytes);
        rand_bytes(nbytes, (uint8_t*) &s[0]);
        return s;
    }

    template<class T>
    std::vector<T> rand_vec(size_t nelem) {
        std::vector<T> buf(nelem);
        rand_bytes(nelem * sizeof(T), (uint8_t*) &buf[0]);
        return buf;
    }

    NTL::ZZ rand_zz_mod(const NTL::ZZ &max) {
        uint8_t buf[NumBits(max)/8 + 1];
        rand_bytes(sizeof(buf), buf);
        return NTL::ZZFromBytes(buf, sizeof(buf)) % max;
    }

    virtual ~PRNG() {}
    virtual void rand_bytes(size_t nbytes, uint8_t *buf) = 0;
    virtual void seed_bytes(size_t nbytes, uint8_t *buf) {
        thrower() << "seed not implemented";
    }
};

class urandom : public PRNG {
 public:
    urandom();
    virtual ~urandom() {}
    virtual void rand_bytes(size_t nbytes, uint8_t *buf);
    virtual void seed_bytes(size_t nbytes, uint8_t *buf);

 private:
    std::fstream f;
};

template<class StreamCipher>
class streamrng : public PRNG {
 public:
    template<typename... ArgTypes>
    streamrng(ArgTypes... args) : c(args...) {}

    virtual void rand_bytes(size_t nbytes, uint8_t *buf) {
        for (size_t i = 0; i < nbytes; i++)
            buf[i] = c.getbyte();
    }

 private:
    StreamCipher c;
};

template<class BlockCipher>
class blockrng : public PRNG {
 public:
    template<typename... ArgTypes>
    blockrng(ArgTypes... args) : bc(args...), ctr(0) {}

    virtual void rand_bytes(size_t nbytes, uint8_t *buf) {
        uint8_t pt[bc.blocksize], ct[bc.blocksize];

        memset(pt, 0, bc.blocksize);
        assert(bc.blocksize >= sizeof(ctr));

        for (size_t i = 0; i < nbytes; i += bc.blocksize) {
            ctr++;
            memcpy(pt, &ctr, sizeof(ctr));
            bc.block_encrypt(pt, ct);

            memcpy(&buf[i], ct, min(bc.blocksize, nbytes - i));
        }
    }

 private:
    BlockCipher bc;
    uint64_t ctr;
};
