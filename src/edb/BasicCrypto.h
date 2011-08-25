/*
 * BasicCrypto.h
 *
 *  Basic symmetric key crypto.
 */

#ifndef BASICCRYPTO_H_
#define BASICCRYPTO_H_

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include "util.h"
#include <map>
#include "params.h"
#include <stdio.h>


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
vector<unsigned char> pad(vector<unsigned char> data, unsigned int unit);
vector<unsigned char> unpad(vector<unsigned char> data);


string
encrypt_AES_CMC(const string &ptext, const AES_KEY * enckey);

string
decrypt_AES_CMC(const string &ctext, const AES_KEY * deckey);



#endif /* BASICCRYPTO_H_ */
