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

vector<unsigned char>
getXorVector(size_t len, const AES_KEY * key, uint64_t salt);

string
encrypt_AES(const string & plaintext, const AES_KEY * key,  uint64_t salt);

string
decrypt_AES(const string & ciphertext, const AES_KEY * key,  uint64_t salt);


#endif /* BASICCRYPTO_H_ */
