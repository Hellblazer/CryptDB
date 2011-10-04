#pragma once

/*
 * BasicCrypto.h
 *
 *  Basic symmetric key crypto.
 */

#include <map>
#include <string>
#include <vector>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/blowfish.h>


AES_KEY * get_AES_KEY(const std::string &key);
AES_KEY * get_AES_enc_key(const std::string & key);
AES_KEY * get_AES_dec_key(const std::string & key);

std::vector<unsigned char>
getXorVector(size_t len, const AES_KEY * key, uint64_t salt);

std::string
encrypt_AES(const std::string & plaintext, const AES_KEY * key,  uint64_t salt);

std::string
decrypt_AES(const std::string & ciphertext, const AES_KEY * key,  uint64_t salt);

std::string
encrypt_AES_CBC(const std::string &ptext, const AES_KEY * enckey, std::string salt, bool pad = true);

std::string
decrypt_AES_CBC(const std::string &ctext, const AES_KEY * deckey, std::string salt, bool pad = true);

//only works for padding unit < 255 bytes
//std::vector<unsigned char> pad(std::vector<unsigned char> data, unsigned int unit);
//std::vector<unsigned char> unpad(std::vector<unsigned char> data);


std::string
encrypt_AES_CMC(const std::string &ptext, const AES_KEY * enckey, bool dopad = true);

std::string
decrypt_AES_CMC(const std::string &ctext, const AES_KEY * deckey, bool dopad = true);


/*
 * Blowfish
 */

#define BF_N 16
struct bf_ctx {
  uint32_t P[BF_N + 2];
  uint32_t S[4][256];
};

class blowfish {
 public:
    blowfish(const std::string &key);
    uint64_t encrypt(uint64_t v);
    uint64_t decrypt(uint64_t v);

 private:
    // BF_KEY k;
    bf_ctx k;
};
