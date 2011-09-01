#pragma once

#include <openssl/aes.h>
#include <string>

class AES {
 public:
    AES(const std::string &key);

    static const size_t blocksize = 16;
    std::string block_encrypt(const std::string &plaintext);
    std::string block_decrypt(const std::string &ciphertext);

 private:
    AES_KEY enc;
    AES_KEY dec;
};
