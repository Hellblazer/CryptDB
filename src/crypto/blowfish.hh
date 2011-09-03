#pragma once

#include <vector>
#include <stdint.h>
#include <openssl/blowfish.h>

#define BF_N 16
struct bf_ctx {
    uint32_t P[BF_N + 2];
    uint32_t S[4][256];
};

class blowfish {
 public:
    blowfish(const std::vector<uint8_t> &key);

    void block_encrypt(const uint8_t *ptext, uint8_t *ctext);
    void block_decrypt(const uint8_t *ctext, uint8_t *ptext);

    static const size_t blocksize = 8;

 private:
    BF_KEY k;
    // bf_ctx k;
};
