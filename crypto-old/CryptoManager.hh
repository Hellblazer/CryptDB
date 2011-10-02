#pragma once

#include <map>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

#include <crypto-old/OPE.hh>
#include <crypto-old/SWPSearch.hh>
#include <crypto-old/BasicCrypto.hh>
#include <util/util.hh>


//returns the highest security level lower than sl that allows equality
SECLEVEL highestEq(SECLEVEL sl);

typedef RSA PKCS;

class CryptoManager {
 private:
    CryptoManager(const CryptoManager &);
    void operator=(const CryptoManager &);

 public:
    CryptoManager(const std::string &masterKey);
    ~CryptoManager();

    //GENERAL FUNCTION for cryptDB
    //unmarshall/marshalls values, deals with types, figure out if
    // encrypt/decrypt, computes the right key, deals with onion levels

    //input: mkey is the master key, the actual key to be used is generated
    // from fullfieldname and tolevel/fromlevel
    //assumes the two levels are one the same onion
    // salt need only be provided for semantic encryptions
    std::string crypt(AES_KEY * mkey, std::string data, fieldType ft,
                 std::string fullfieldname, SECLEVEL fromlevel, SECLEVEL tolevel, bool & isBin,
                 uint64_t salt = 0);

    //generates a randomness pool for Paillier
    void generateRandomPool(unsigned int randomPoolSize, std::string file);

    static AES_KEY * getKey(const std::string & key);

    //SPECIFIC FUNCTIONS

    //expects AES_KEY_BYTES long key
    void setMasterKey(const std::string &masterKey);

    //**** Public Key Cryptosystem (PKCS) *****//

    static const unsigned int PKCS_bytes_size = 256;     //this is the size in
                                                         // openssl

    //generates a new key
    static void generateKeys(PKCS * & pk, PKCS * & sk);

    //marshalls a key
    //if ispk is true, it returns the binary of the public key and sets let to
    // the length returned
    //is !ispk, it does the same for secret key
    static std::string marshallKey(PKCS * mkey, bool ispk);

    //from a binary key of size keylen, it returns a public key if ispk, else
    // a secret key
    static PKCS * unmarshallKey(const std::string &key, bool ispk);

    //using key, it encrypts the data in from of size fromlen
    //the result is len long
    static std::string encrypt(PKCS * key, const std::string &from);

    //using key, it decrypts data at fromcipher, and returns the decrypted
    // value
    static std::string decrypt(PKCS * key, const std::string &fromcipher);

    //frees memory allocated by this keyb
    static void freeKey(PKCS * key);

    //***************************************************************************************/

    uint32_t encrypt_VAL(std::string uniqueFieldName, uint32_t value,
                         uint64_t salt);
    //result len is same as input len
    std::string encrypt_VAL(std::string uniqueFieldName, std::string value, uint64_t salt);


    //SEMANTIC
    //since many values may be encrypted with same key you want to set the key
    static AES_KEY * get_key_SEM(const std::string &key);
    static uint64_t encrypt_SEM(uint64_t ptext, AES_KEY * key, uint64_t salt);
    static uint64_t decrypt_SEM(uint64_t ctext, AES_KEY * key, uint64_t salt);
    static uint32_t encrypt_SEM(uint32_t ptext, AES_KEY * key, uint64_t salt);
    static uint32_t decrypt_SEM(uint32_t ctext, AES_KEY * key, uint64_t salt);

    //output same len as input
    static std::string encrypt_SEM(const std::string &ptext, AES_KEY *key,
            uint64_t salt);
    static std::string decrypt_SEM(const std::string &ctext, AES_KEY *key,
            uint64_t salt);



/*    static AES_KEY * get_key_DET(const std::string &key);
    static uint64_t encrypt_DET(uint64_t plaintext, BF_KEY * key);
    static uint64_t decrypt_DET(uint64_t ciphertext, BF_KEY * key);

    static std::string encrypt_DET(const std::string & plaintext, AES_KEY * key);
    static std::string decrypt_DET(const std::string & ciphertext, AES_KEY * key);
*/

    /**
     * Returns the key corresponding to the security level given for some
     * master key and some unique field name. Result will be AES_KEY_SIZE
     * long.
     */
    std::string getKey(const std::string &uniqueFieldName, SECLEVEL sec);
    std::string getKey(AES_KEY * mkey, const std::string &uniqueFieldName, SECLEVEL sec);

    static std::string marshallKey(const std::string &key);
    static std::string unmarshallKey(const std::string &key);

    //int32_t encrypt_SEM(int32_t ptext, int salt, unsigned char * key);
    //int32_t decrypt_SEM(int32_t, const char * ctext, unsigned char * salt,
    // unsigned char * key);

    //OPE
    static OPE * get_key_OPE(const std::string &key, const unsigned int & pTextBytes = OPE_PLAINTEXT_SIZE,
            const unsigned int & cTextBytes = OPE_CIPHERTEXT_SIZE);     //key must have
    // OPE_KEY_SIZE
    static uint64_t encrypt_OPE(uint32_t plaintext, OPE * ope);
    static uint32_t decrypt_OPE(uint64_t ciphertext, OPE * ope);
    // used to encrypt text
    static uint64_t encrypt_OPE_text_wrapper(const std::string & plaintext,
            OPE * ope);
    static std::string encrypt_OPE(const std::string &plaintext, OPE * ope);
    static std::string decrypt_OPE(const std::string &ciphertext, OPE * ope);

    uint64_t encrypt_OPE(uint32_t plaintext, std::string uniqueFieldName);
    uint64_t
    encrypt_OPE_enctables(uint32_t val, std::string uniqueFieldName);

    /*
     * SEARCH
     *
     * Two methods:
     * 1. faster and less secure: encrypt each word with DET separately
     * 2. slower and more secure: use SWP method
     */

    /* Method 1 */
    // was integrated in older versions, not in current version

    //encrypts a std::string such that it can support search, ciph need not be
    // initialized
    // input len must be set to the sum of the lengths of the words and it
    // will be updated to the length of the ciphertext
    static std::string encrypt_DET_search(std::list<std::string> * words, AES_KEY * key);
    static std::list<std::string> * decrypt_DET_search(const std::string &ctext,
                                             AES_KEY * key);

    static std::string encrypt_DET_wrapper(const std::string &ptext, AES_KEY * key);
    static std::string decrypt_DET_wrapper(const std::string &ctext, AES_KEY * key);

    /* Method 2 */
    static Binary encryptSWP(const Binary & key, const std::list<Binary> & words);
    static std::list<Binary> * decryptSWP(const Binary & key,
                                     const Binary & overall_ciph);
    static Token token(const Binary & key, const Binary & word);
    static std::list<unsigned int> * searchSWP(const Token & token,
                                          const Binary & overall_ciph);
    static bool searchExists(const Token & token, const Binary & overall_ciph);

    //aggregates
    static const unsigned int Paillier_len_bytes = PAILLIER_LEN_BYTES;
    static const unsigned int Paillier_len_bits = Paillier_len_bytes * 8;
    std::string encrypt_Paillier(uint64_t val);
    int decrypt_Paillier(const std::string &ciphertext);

    std::string getPKInfo();
    AES_KEY * getmkey();

    //ENCRYPTION TABLES

    /*
    //will create encryption tables and will use them
    //noOPE encryptions and noHOM encryptions
    void createEncryptionTables(int noOPE, int noHOM,
                                std::list<string>  fieldsWithOPE);
    void replenishEncryptionTables();
     */

    void loadEncTables(const std::string &filename);

    //TODO:
    //batchEncrypt
    //batchDecrypt

 private:
    AES_KEY * masterKey;

    //Paillier cryptosystem
    NTL::ZZ Paillier_lambda, Paillier_n, Paillier_g, Paillier_n2;
    NTL::ZZ Paillier_p, Paillier_q;
    NTL::ZZ Paillier_p2, Paillier_q2;
    NTL::ZZ Paillier_2n, Paillier_2p, Paillier_2q;
    NTL::ZZ Paillier_ninv, Paillier_pinv, Paillier_qinv;
    NTL::ZZ Paillier_hp, Paillier_hq;
    NTL::ZZ Paillier_dec_denom;     //L(g^lambda mod n^2)
    NTL::ZZ Paillier_a;
    bool Paillier_fast;

    //encryption tables
    bool useEncTables;
    int noOPE, noHOM;
    std::map<std::string, std::map<uint32_t, uint64_t> *> OPEEncTable;
    //todo: one HOM enc should not be reused
    std::map<uint64_t, std::string > HOMEncTable;
    std::list<NTL::ZZ> HOMRandCache;

    bool VERBOSE;

};
