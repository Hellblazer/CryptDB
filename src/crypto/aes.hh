#pragma once

#include <openssl/aes.h>
#include <string>

class AES {
 public:
    AES(const std::string &key);

    static uint blocksize() { return 16; }
    std::string block_encrypt(const std::string &plaintext);
    std::string block_decrypt(const std::string &ciphertext);

 private:
    AES_KEY enc;
    AES_KEY dec;
};
