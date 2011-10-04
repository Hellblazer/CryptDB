#pragma once

#include <assert.h>

template<class Hash>
class hmac {
 public:
    hmac(const void *keydata, size_t keylen) {
        assert(Hash::blocksize >= Hash::hashsize);

        uint8_t k[Hash::blocksize];
        memset(k, 0, sizeof(k));
        if (keylen <= Hash::blocksize) {
            memcpy(k, keydata, keylen);
        } else {
            Hash kh;
            kh.update(keydata, keylen);
            kh.final(k);
        }

        for (size_t i = 0; i < Hash::blocksize; i++) {
            opad[i] = k[i] ^ 0x5c;
            ipad[i] = k[i] ^ 0x36;
        }

        h.update(ipad, sizeof(ipad));
    }

    void update(const void *data, size_t len) {
        h.update(data, len);
    }

    void final(uint8_t *buf) {
        uint8_t inner[Hash::hashsize];
        h.final(inner);

        Hash outer;
        outer.update(opad, sizeof(opad));
        outer.update(inner, sizeof(inner));
        outer.final(buf);
    }

    std::vector<uint8_t> final() {
        std::vector<uint8_t> v(Hash::hashsize);
        final(&v[0]);
        return v;
    }

#define mac_type(DTYPE, KTYPE)                                              \
    static std::vector<uint8_t> mac(const DTYPE &v, const KTYPE &key) {     \
        hmac x(&key[0], key.size());                                        \
        x.update(&v[0], v.size());                                          \
        return x.final();                                                   \
    }

    mac_type(std::string, std::string)
    mac_type(std::string, std::vector<uint8_t>)
    mac_type(std::vector<uint8_t>, std::string)
    mac_type(std::vector<uint8_t>, std::vector<uint8_t>)
#undef mac_type

 private:
    uint8_t opad[Hash::blocksize];
    uint8_t ipad[Hash::blocksize];
    Hash h;
};
