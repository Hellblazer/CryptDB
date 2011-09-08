#pragma once

#include <openssl/aes.h>
#include <vector>

class AES {
 public:
    AES(const std::vector<uint8_t> &key) {
        assert(key.size() == 16 || key.size() == 24 || key.size() == 32);
        AES_set_encrypt_key(&key[0], key.size() * 8, &enc);
        AES_set_decrypt_key(&key[0], key.size() * 8, &dec);
    }

    void block_encrypt(const uint8_t *ptext, uint8_t *ctext) {
        AES_encrypt(ptext, ctext, &enc);
    }

    void block_decrypt(const uint8_t *ctext, uint8_t *ptext) {
        AES_decrypt(ctext, ptext, &dec);
    }

    static const size_t blocksize = 16;

 private:
    AES_KEY enc;
    AES_KEY dec;
};
