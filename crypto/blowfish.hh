#pragma once

#include <vector>
#include <stdint.h>
#include <openssl/blowfish.h>

class blowfish {
 public:
    blowfish(const std::vector<uint8_t> &key) {
        BF_set_key(&k, key.size(), &key[0]);
    }

    void block_encrypt(const uint8_t *ptext, uint8_t *ctext) const {
        BF_ecb_encrypt(ptext, ctext, &k, BF_ENCRYPT);
    }

    void block_decrypt(const uint8_t *ctext, uint8_t *ptext) const {
        BF_ecb_encrypt(ctext, ptext, &k, BF_DECRYPT);
    }

    static const size_t blocksize = 8;

 private:
    BF_KEY k;
};
