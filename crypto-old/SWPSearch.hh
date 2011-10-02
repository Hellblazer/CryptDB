/*
 * Crypto.h
 *
 *
 *      Author: raluca
 *
 *      Implementation of the Song-Wagner-Perrig cryptosystem, 2000
 *
 *      TODO: interpret "%" in searches
 *      TODO: because of the way we use their protocol, we can simplify their encryption scheme  by
 *        -- (implemented) no need for Si = PRP_k(i), any random Si is enough (in cases where we do not care of decryption)
 *        -- the ciphertext can be made shorter as long as it does not cause a collision
 *            -- Si   and F_ki(Si) being the same for the same word, and Si matching Fki(Si) for an incorrect search matching (false positive in search)
 *            or SWPCiphertext size making different words encrypted to match to the same deterministic encryption E[W]
 *            -- suggestion: Si and F each 32bits
 *        -- removind a layer of PRP/encryption given by the counter
 */

#ifndef SWPSEARCH_H_
#define SWPSEARCH_H_

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <list>

#include <util/util.hh>
#include <crypto-old/Binary.hh>


// for all following constants unit is bytes

const unsigned int SWPCiphSize = 16; // must be <= 16
const unsigned int SWPm = 4; //the rate of false positives when searching is
                             // 1/2^{m*8}
const unsigned int SWP_SALT_LEN = 8; //the size of salt in bytes
const unsigned int SWPr = SWPCiphSize - SWPm;

typedef struct Token {
    Binary ciph;
    Binary wordKey;
} Token;

class SWP {
 public:
    /*
     * Encrypts the list of words with key.
     *
     * Requires: each word < SWPCiphSize.
     *
     * Returns: NULL on problem.
     */

    static list<Binary> * encrypt(const Binary & key,
                                  const list<Binary> & words);

    /*
     * Decrypts each word in the list ciphs.
     *
     * Decryption only works and should be called if SWPCiphSize is multiple
     * of AES_BLOCK_BITS (see canDecrypt flag)
     *
     */

    static list<Binary> * decrypt(const Binary & key,
                                  const list<Binary> & ciphs);

    /*
     * Given the secret key and the word to search for, returns the token to
     * be used during searching.
     */
    static Token token(const Binary & key, const Binary & word);

    /*
     * Returns a list of indexes of words in the list of ciphertexts ciphs
     * that match the token based on SWP or a boolean indicating whether
     * the value exists in the given ciphertexts or not.
     */
    static list<unsigned int> * search(const Token & token,
                                       const list<Binary> & ciphs);
    static bool searchExists(const Token & token, const list<Binary> & ciphs);

    static const bool canDecrypt = (SWPCiphSize % AES_BLOCK_SIZE == 0);

    /** PRP **/

     // Computes PRP_{key}(val), where PRP is a pseudorandom permutation
     // Result is empty on problem
     static Binary PRP(const Binary & key, const Binary & val);

 private:


    /* Symmetric key crypto -- AES
     * requires: iv of AES_BLOCK_BYTES */

    static Binary encryptSym(const Binary & key, const Binary & val,
                             const Binary & iv);
    static Binary decryptSym(const Binary & key, const Binary & ciph,
                             const Binary & iv);

    /*
     * AES semantic (probabilistic) secure encryption
     * some salt is chosen randomly and appended to the ciphertext
     */
    static Binary encryptSym(const Binary & key, const Binary & val);
    static Binary decryptSym(const Binary & key, const Binary & ciph);

    //returns a random binary that has nobytes, chosen at random
    static Binary random(unsigned int nobytes);

    /*
     * SWP helper functions
     */

    static Binary SWPencrypt(const Binary & key, Binary word,
                             unsigned int index);
    static Binary SWPdecrypt(const Binary & key, const Binary & word,
                             unsigned int index);

    static bool SWPsearch(const Token & token, const Binary & ciph);

    static void SWPHalfEncrypt(const Binary & key, Binary word, Binary & ciph,
                               Binary & wordKey);

};

#endif /* SWPSEARCH_H_ */
