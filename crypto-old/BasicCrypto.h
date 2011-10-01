/*
 * BasicCrypto.h
 *
 *  Basic symmetric key crypto.
 */

#ifndef BASICCRYPTO_H_
#define BASICCRYPTO_H_

#include <map>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/blowfish.h>
#include <util/util.h>


AES_KEY * get_AES_KEY(const string &key);
AES_KEY * get_AES_enc_key(const string & key);
AES_KEY * get_AES_dec_key(const string & key);

vector<unsigned char>
getXorVector(size_t len, const AES_KEY * key, uint64_t salt);

string
encrypt_AES(const string & plaintext, const AES_KEY * key,  uint64_t salt);

string
decrypt_AES(const string & ciphertext, const AES_KEY * key,  uint64_t salt);

string
encrypt_AES_CBC(const string &ptext, const AES_KEY * enckey, string salt, bool pad = true);

string
decrypt_AES_CBC(const string &ctext, const AES_KEY * deckey, string salt, bool pad = true);

//only works for padding unit < 255 bytes
//vector<unsigned char> pad(vector<unsigned char> data, unsigned int unit);
//vector<unsigned char> unpad(vector<unsigned char> data);


string
encrypt_AES_CMC(const string &ptext, const AES_KEY * enckey, bool dopad = true);

string
decrypt_AES_CMC(const string &ctext, const AES_KEY * deckey, bool dopad = true);


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
    blowfish(const string &key);
    uint64_t encrypt(uint64_t v);
    uint64_t decrypt(uint64_t v);

 private:
    // BF_KEY k;
    bf_ctx k;
};

#endif /* BASICCRYPTO_H_ */
