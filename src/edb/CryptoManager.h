#ifndef _CRYPTOMANAGER_H
#define _CRYPTOMANAGER_H

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include "util.h"
#include <map>
#include "OPE.h"
#include "params.h"
#include <stdio.h>


//returns the highest security level lower than sl that allows equality
SECLEVEL highestEq(SECLEVEL sl);

typedef RSA PKCS;

class CryptoManager {
    
    public:	
	CryptoManager(unsigned char * masterKey);
	~CryptoManager();
	

    //GENERAL FUNCTION for cryptDB
	//unmarshall/marshalls values, deals with types, figure out if encrypt/decrypt, computes the right key, deals with onion levels

   //input: mkey is the master key, the actual key to be used is generated from fullfieldname and tolevel/fromlevel
   //assumes the two levels are one the same onion
   // salt need only be provided for semantic encryptions
   string crypt(AES_KEY * mkey, string data, fieldType ft, string fullfieldname, SECLEVEL fromlevel, SECLEVEL tolevel,
		   uint64_t salt = 0);

	//SPECIFIC FUNCTIONS

	//expects AES_KEY_BYTES long key
	void setMasterKey(unsigned char * masterKey);

	//TODO: these: make one function for the same onion as well as for multiple levels
	// encrypt with ope onion: value -> opeself -> sem
	uint64_t encrypt_OPE_onion(string  uniqueFieldName, uint32_t value, uint64_t salt);
	//encrypt with det onion: value -> DET -> sem
	uint64_t encrypt_DET_onion(string  uniqueFieldName, uint32_t value, uint64_t salt);
	uint64_t encrypt_DET_onion(string  uniqueFieldName, string value, uint64_t salt);
	

	//**************** Public Key Cryptosystem (PKCS) ****************************************/

	static const unsigned int PKCS_bytes_size = 256; //this is the size in openssl

	//generates a new key
	static void generateKeys(PKCS * & pk, PKCS * & sk);

	//marshalls a key
	//if ispk is true, it returns the binary of the public key and sets let to the length returned
	//is !ispk, it does the same for secret key
	static binary marshallKey(PKCS * mkey, bool ispk, int & len);

	//from a binary key of size keylen, it returns a public key if ispk, else a secret key
	static PKCS * unmarshallKey(binary key, int keylen, bool ispk);

	//using key, it encrypts the data in from of size fromlen
	//the result is len long
	static binary encrypt(PKCS * key, unsigned char * from, int fromlen, int & len);

	//using key, it decrypts data at fromcipher, and returns the decrypted value
	static binary decrypt(PKCS * key, unsigned char * fromcipher, int fromlen, int & len);

	//frees memory allocated by this keyb
	static void freeKey(PKCS * key);


	//***************************************************************************************/

	//len will contain the size of the ciphertext
	unsigned char * encrypt_text_DET_onion(string uniqueFieldName, string value, uint64_t salt, unsigned int & len);



	uint32_t encrypt_VAL(string  uniqueFieldName, uint32_t value, uint64_t salt);
	//result len is same as input len
	unsigned char *encrypt_VAL(string uniqueFieldName, string value, uint64_t salt);
	
	/**
	* Returns the key corresponding to the security level given for some master key and 
	* some unique field name. Result will be AES_KEY_SIZE long.  
	*/
	unsigned char* getKey(string uniqueFieldName, SECLEVEL sec);
	unsigned char * getKey(AES_KEY * mkey, string uniqueFieldName, SECLEVEL sec);
	
	static string marshallKey(const unsigned char * key);
	static unsigned char * unmarshallKey(string key);
	
	//int32_t encrypt_SEM(int32_t ptext, int salt, unsigned char * key);
	//int32_t decrypt_SEM(int32_t, const char * ctext, unsigned char * salt, unsigned char * key);
	
	//SEMANTIC
	//since many values may be encrypted with same key you want to set the key
	static AES_KEY * get_key_SEM(const unsigned char * key);
	static uint64_t encrypt_SEM(uint64_t ptext, AES_KEY * key, uint64_t salt);
	static uint64_t decrypt_SEM(uint64_t ctext, AES_KEY * key, uint64_t salt);
	static uint32_t encrypt_SEM(uint32_t ptext, AES_KEY * key, uint64_t salt);
	static uint32_t decrypt_SEM(uint32_t ctext, AES_KEY * key, uint64_t salt);
	//output same len as input
	static unsigned char *encrypt_SEM(string ptext, AES_KEY*key, uint64_t salt);
	
	//static string decrypt_SEM_toString(unsigned char *etext, unsigned int elen, AES_KEY*key, uint64_t salt);

	static unsigned char * encrypt_SEM(unsigned char * & ptext, unsigned int len, AES_KEY * key, uint64_t salt);
	static unsigned char * decrypt_SEM(unsigned char * ctext, unsigned int len, AES_KEY * key, uint64_t salt);

	
	//OPE
	static OPE * get_key_OPE(unsigned char * key); //key must have OPE_KEY_SIZE
	static uint64_t encrypt_OPE(uint32_t plaintext, OPE * ope);
	static uint32_t decrypt_OPE(uint64_t ciphertext, OPE * ope);
	static unsigned char * encrypt_OPE(unsigned char * plaintext, OPE * ope);
	static unsigned char * decrypt_OPE(unsigned char * ciphertext, OPE * ope);
	// used to encrypt text
	static uint64_t encrypt_OPE_text_wrapper(const string & plaintext, OPE * ope);
	uint64_t encrypt_OPE(uint32_t plaintext, string uniqueFieldName);

	//DET: one-way functions
	static AES_KEY * get_key_DET (const unsigned char * key);
	static uint64_t encrypt_DET(uint32_t plaintext, AES_KEY * key);
	static uint64_t encrypt_DET(uint64_t plaintext, AES_KEY * key);
	static uint64_t encrypt_DET(string plaintext, AES_KEY *key);
	static uint64_t decrypt_DET(uint64_t ciphertext, AES_KEY * key);

	//encrypts a string such that it can support search, ciph need not be initialized
	// input len must be set to the sum of the lengths of the words and it will be updated to the length of the ciphertext
	static void encrypt_DET_search(list<string> * words, AES_KEY * key, unsigned char * & ciph, unsigned int & len);
	static list<string> * decrypt_DET_search(unsigned char * ciph, unsigned int len,  AES_KEY * key);

	static unsigned char * encrypt_DET_wrapper(string text, AES_KEY * key, unsigned int & len);
	static string decrypt_DET_wrapper(unsigned char * ctext, unsigned int len, AES_KEY * key);

	//aggregates
	static const unsigned int Paillier_len_bytes = PAILLIER_LEN_BYTES;
	static const unsigned int Paillier_len_bits = Paillier_len_bytes * 8;
	unsigned char * encrypt_Paillier(int val);
	int decrypt_Paillier(unsigned char * ciphertext);

	unsigned char * getPKInfo();
	AES_KEY * getmkey();


    //ENCRYPTION TABLES

    //will create encryption tables and will use them
    //noOPE encryptions and noHOM encryptions
    void createEncryptionTables(int noOPE, int noHOM, list<string>  fieldsWithOPE);
    void replenishEncryptionTables();


	//TODO:
	//batchEncrypt
	//batchDecrypt
	
    private:
    
	AES_KEY * masterKey;
	unsigned char * masterKeyBytes;

	//Paillier cryptosystem
	ZZ Paillier_lambda, Paillier_n, Paillier_g, Paillier_n2;
	ZZ Paillier_dec_denom; //L(g^lambda mod n^2)
	
	//encryption tables
	bool useEncTables;
	int noOPE, noHOM;
	map<string, map<int, uint64_t> > OPEEncTable;
	map<int, list<unsigned char *> > HOMEncTable;

	bool VERBOSE;



};

#endif   /* _CRYPTOMANAGER_H */
