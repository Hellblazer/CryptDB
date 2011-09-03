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

    void block_encrypt(const uint8_t *plaintext, uint8_t *ciphertext) {
        AES_encrypt(plaintext, ciphertext, &enc);
    }

    void block_decrypt(const uint8_t *ciphertext, uint8_t *plaintext) {
        AES_decrypt(ciphertext, plaintext, &dec);
    }

    static const size_t blocksize = 16;

 private:
    AES_KEY enc;
    AES_KEY dec;
};
