/*
 * Crypto.cpp
 *
 *
 *      Author: raluca
 */

#include "SWPSearch.h"
#include <iostream>


unsigned char fixedIV[] = {34, 145, 42, 12, 56, 13, 111, 100, 98, 6, 2, 63, 88, 4, 22, 74};

static Binary iv_det;

static const bool DEBUG = false;



Binary SWP::PRP(const Binary & key, const Binary & val) {

	return encryptSym(key, val, key);

}

/*************** Sym key crypto ******************/

//pads with 10..00 making length of result be a multiple of len (bytes)
static Binary pad(const Binary & vec, unsigned int len) {

	Binary result;
	if (vec.len % len == 0) {
		result.len = vec.len + len;
	} else {
		result.len = (vec.len / len + 1) * len;
	}

	result.content = new unsigned char[result.len];

	memcpy(result.content, vec.content, vec.len);

	result.content[vec.len] = 1;

	for (unsigned int i = vec.len+1; i < result.len ; i++) {
		result.content[i] = 0;
	}

	return result;

}


static Binary unpad(const Binary & vec) {

	int index = vec.len - 1;

	while ((index > 0) && (vec.content[index] == 0)) {
		index--;
	}

	assert_s((index>=0) && (vec.content[index] == 1), "input was not padded correctly");

	return vec.subbinary(0, index);
}

Binary SWP::encryptSym(const Binary & key, const Binary & val, const Binary & iv) {

	assert_s(iv.len == AES_BLOCK_SIZE, "iv has incorrect length");
	assert_s(key.len == AES_BLOCK_SIZE, "key has incorrect length");

	AES_KEY aes_key;

	Binary newiv(iv);

	AES_set_encrypt_key(key.content, AES_BLOCK_BITS, &aes_key);

	Binary val2(pad(val, AES_BLOCK_SIZE));

	Binary result(val2.len);

	AES_cbc_encrypt(val2.content, result.content, val2.len, &aes_key, newiv.content, AES_ENCRYPT);
	return result;
}

Binary SWP::decryptSym(const Binary & key, const Binary & ciph, const Binary & iv) {

	assert_s(iv.len == AES_BLOCK_SIZE, "iv has incorrect length");
	assert_s(key.len == AES_BLOCK_SIZE, "key has incorrect length");

	AES_KEY aes_key;

	Binary newiv(iv);

	AES_set_decrypt_key(key.content, AES_BLOCK_BITS, &aes_key);

	Binary result(ciph.len);


	AES_cbc_encrypt(ciph.content, result.content, ciph.len, &aes_key, newiv.content, AES_DECRYPT);

	return unpad(result);

}


Binary SWP::encryptSym(const Binary & key, const Binary & val) {
	Binary salt = random(SWP_SALT_LEN);
	Binary iv = PRP(key, salt);
	Binary ciph = encryptSym(key, val, iv);

	return salt+ciph;
}

Binary SWP::decryptSym(const Binary & key, const Binary & ciph) {
	Binary salt = ciph.subbinary(0, SWP_SALT_LEN);
	Binary iv = PRP(key, salt);
	Binary ciph2 = ciph.subbinary(SWP_SALT_LEN, ciph.len - SWP_SALT_LEN);

	return decryptSym(key, ciph2, iv);
}

Binary SWP::random(unsigned int nobytes) {
	Binary bin = Binary();
	bin.len = nobytes;
	bin.content = new unsigned char[bin.len];
	RAND_bytes(bin.content, bin.len);

	return bin;
}


/**************************** SWP ****************/


// this function performs half of the encrypt job up to the point at which tokens are generated
void SWP::SWPHalfEncrypt(const Binary & key, Binary word, Binary & ciph, Binary & wordKey) {
	//encryption of word E[W_i]
	ciph = encryptSym(key, word, Binary(AES_BLOCK_SIZE, fixedIV));

	//L_i and R_i
	Binary L_i;
	if (SWP::canDecrypt) {
		L_i = ciph.subbinary(0, SWPr);
	}

	//wordKey: k_i = PRP_{key}(E[W_i])

	if (!SWP::canDecrypt) {
		wordKey = PRP(key, ciph);
	} else {
		wordKey = PRP(key, L_i);
	}
}


Binary SWP::SWPencrypt(const Binary & key, Binary word, unsigned int index) {

	if (DEBUG) {cerr << "encrypting " << word.toString() << "\n ";}
	Binary ciph, wordKey;

	SWPHalfEncrypt(key, word, ciph, wordKey);

	//S_i
	Binary salt = PRP(key, Binary::toBinary(index));
	salt = salt.subbinary(salt.len - SWPr, SWPr);


	//F_{k_i} (S_i)
	Binary func = PRP(wordKey, salt);

	if (SWP::canDecrypt) {
		func = func.subbinary(SWPr, SWPm);
	}

	return ciph ^ (salt + func);

}

Token SWP::token(const Binary & key, const Binary & word) {
	Token t = Token();

	SWPHalfEncrypt(key, word, t.ciph, t.wordKey);

	return t;

}

bool SWP::SWPsearch(const Token & token, const Binary & ciph) {

	if (DEBUG) { cerr << "searching! \n"; }

	//remove E[W_i]
	Binary ciph2 = ciph ^ token.ciph;

	//remains salt, PRP(wordkey, salt)
	Binary salt = ciph2.subbinary(0, SWPr);
	Binary funcpart = ciph2.subbinary(SWPr, ciph2.len - SWPr);

	Binary func = PRP(token.wordKey, salt);
	if (SWP::canDecrypt) {
		func = func.subbinary(SWPr, SWPm);
	}

	if (func == funcpart) {
		return true;
	}

	return false;
}




list<Binary> * SWP::encrypt(const Binary & key, const list<Binary> & words) {

	list<Binary> * result = new list<Binary>();

	unsigned int index = 0;

	for (list<Binary>::const_iterator it = words.begin(); it != words.end(); it++) {
		index++;

		Binary word = *it;

		assert_s(word.len < SWPCiphSize, string(" given word ") + word.toString() + " is longer than SWPCiphSize");

		result->push_back(SWPencrypt(key, word, index));
	}

	return result;
}

Binary SWP::SWPdecrypt(const Binary & key, const Binary & word, unsigned int index) {

	//S_i
	Binary salt = PRP(key, Binary::toBinary(index));
	salt = salt.subbinary(salt.len - SWPr, SWPr);

	//L_i
	Binary L_i = salt ^ word.subbinary(0, SWPr);

	//k_i
	Binary wordKey = PRP(key, L_i);

	//F_{k_i} (S_i)
	Binary func = PRP(wordKey, salt).subbinary(SWPr, SWPm);

	Binary R_i = func ^ word.subbinary(SWPr, SWPm);

	return decryptSym(key, L_i + R_i, Binary(AES_BLOCK_SIZE, fixedIV));

}

list<Binary> * SWP::decrypt(const Binary & key, const list<Binary>  & ciph) {
	list<Binary> * result = new list<Binary>();

	assert_s(canDecrypt, "the current choice of parameters for SWP does not allow decryption");

	unsigned int index = 0;

	for (list<Binary>::const_iterator it = ciph.begin(); it != ciph.end(); it++) {
		index++;

		Binary word = *it;

		assert_s(word.len == SWPCiphSize, " given ciphertext with invalid length ");

		result->push_back(SWPdecrypt(key, word, index));

	}

	return result;
}


list<unsigned int> * SWP::search(const Token & token, const list<Binary> & ciphs) {
	list<unsigned int> * res = new list<unsigned int>();

	unsigned int index = 0;
	for (list<Binary>::const_iterator cit = ciphs.begin(); cit != ciphs.end(); cit++) {
		if (SWPsearch(token, *cit)) {
			res->push_back(index);
		}
		index++;
	}

	return res;
}



bool SWP::searchExists(const Token & token, const list<Binary> & ciphs) {

	for (list<Binary>::const_iterator cit = ciphs.begin(); cit != ciphs.end(); cit++) {
		if (SWPsearch(token, *cit)) {
			return true;
		}
	}

	return false;
}

