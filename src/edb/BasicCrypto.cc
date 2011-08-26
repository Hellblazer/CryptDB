/*
 * BasicCrypto.cc
 *
 *
 */

#include <assert.h>
#include "BasicCrypto.h"
#include "ctr.hh"


AES_KEY *
get_AES_KEY(const string &key)
{
    return get_AES_enc_key(key);

}

AES_KEY *
get_AES_enc_key(const string &key)
{
    ANON_REGION(__func__, &perf_cg);

    AES_KEY * aes_key = new AES_KEY();

    if (AES_set_encrypt_key((const uint8_t*) key.c_str(), AES_KEY_SIZE,
            aes_key) <0) {
        myassert(false, "problem with AES set encrypt ");
    }

    return aes_key;
}


AES_KEY *
get_AES_dec_key(const string &key)
{
    ANON_REGION(__func__, &perf_cg);

    AES_KEY * aes_key = new AES_KEY();

    if (AES_set_decrypt_key((const uint8_t*) key.c_str(), AES_KEY_SIZE,
                            aes_key) <0) {
        myassert(false, "problem with AES set encrypt ");
    }

    return aes_key;

}


template<typename SIZE_T>
static SIZE_T
getBlocks(unsigned int unit, SIZE_T len) {
    SIZE_T blocks = len / unit;
    if (len > blocks * unit) {
        blocks++;
    }
    return blocks;
}


vector<unsigned char>
getXorVector(size_t len, const AES_KEY * key, uint64_t salt)
{
    size_t AESBlocks = len / AES_BLOCK_BYTES;
    if (AESBlocks * AES_BLOCK_BYTES < len) {
        AESBlocks++;
    }

    //construct vector with which we will XOR
    vector<unsigned char> v(AESBlocks * AES_BLOCK_BYTES);

    for (unsigned int i = 0; i < AESBlocks; i++) {
        AES_encrypt((const uint8_t*) BytesFromInt(salt+i,
                                                  AES_BLOCK_BYTES).c_str(),
                    &v[i*AES_BLOCK_BYTES], key);
    }
    return v;
}


string
encrypt_AES(const string &ptext, const AES_KEY * key, uint64_t salt)
{
    vector<unsigned char> xorVector = getXorVector(ptext.length(), key, salt);

    stringstream ss;
    for (unsigned int i = 0; i < ptext.length(); i++) {
        ss << (uint8_t) (((uint8_t)ptext[i]) ^ xorVector[i]);
    }

    return ss.str();
}

string
decrypt_AES(const string &ctext, const AES_KEY * key, uint64_t salt)
{
    vector<unsigned char> xorVector = getXorVector(ctext.length(), key, salt);

    stringstream ss;
    for (unsigned int i = 0; i < ctext.length(); i++)
        ss << (uint8_t) (((uint8_t)ctext[i]) ^ xorVector[i]);

    return ss.str();
}

static vector<unsigned char>
getIVec(string salt)
{
    vector<unsigned char> ivec(AES_BLOCK_BYTES);

    memcpy(&ivec[0], salt.data(), min(salt.length(), (size_t) AES_BLOCK_BYTES));

    return ivec;
}

static vector<unsigned char>
pad(vector<unsigned char> data, unsigned int unit)
{
    assert_s(unit < 256, "pad does not work for padding unit more than 256 bytes");
    size_t blocks = getBlocks(unit, data.size());
    size_t multipleLen = blocks * unit;
    size_t padding;
    if (multipleLen == data.size()) {
        padding = unit;
    } else {
        padding = multipleLen - data.size();
    }
    size_t paddedLen = data.size() + padding;

    // cerr << "length of padding " << padding << " length of padded data " << paddedLen << "\n";

    vector<unsigned char> res(paddedLen, 0);
    res[paddedLen-1] = (unsigned char)padding;
    memcpy(&res[0], &data[0], data.size());
    return res;
}

static vector<unsigned char>
unpad(vector<unsigned char> data)
{
    size_t len = data.size();
    // cerr << "padding to remove " << (int)data[len-1] << "\n";
    size_t actualLen = len - (int)data[len-1];
    // cerr << " len is " << len << " and data[len-1] " << (int)data[len-1] << "\n";
    assert_s(data[len-1] <= len, "invalid pad value when unpadding");
    vector<unsigned char> res(actualLen);
    memcpy(&res[0], &data[0], actualLen);
    return res;
}


string
encrypt_AES_CBC(const string &ptext, const AES_KEY * enckey, string salt, bool dopad)
{
    //TODO: separately for numbers to avoid need for padding

    assert(dopad || ((ptext.size() % 16) == 0));

    vector<unsigned char> ptext_buf;
    if (dopad) {
        ptext_buf = pad(vector<unsigned char>(ptext.begin(), ptext.end()), AES_BLOCK_BYTES);
        // cerr << "padded data is " << stringToByteInts(string((char *) &ptext_buf[0], ptext_buf.size())) << "\n";
    } else {
        ptext_buf = vector<unsigned char>(ptext.begin(), ptext.end());
    }
    auto ctext_buf = vector<unsigned char>(ptext_buf.size());
    auto ivec = getIVec(salt);

    AES_cbc_encrypt(&ptext_buf[0], &ctext_buf[0], ptext_buf.size(), enckey, &ivec[0], AES_ENCRYPT);

    // cerr << "encrypted data is " << stringToByteInts(string((char *) &ctext_buf[0], ctext_buf.size())) << '\n';

    return string((char *) &ctext_buf[0], ctext_buf.size());
}

string
decrypt_AES_CBC(const string &ctext, const AES_KEY * deckey, string salt, bool dounpad)
{
    assert((ctext.size() % 16) == 0);

    vector<unsigned char> ptext_buf(ctext.size());
    auto ivec = getIVec(salt);

    AES_cbc_encrypt((const unsigned char *) ctext.data(), &ptext_buf[0], ctext.size(), deckey, &ivec[0], AES_DECRYPT);


    if (dounpad) {
        auto res = unpad(ptext_buf);
        // cerr << "unpadded dec data is " << stringToByteInts(string((char * ) &res[0], res.size())) << "\n";
        return string((char *)&res[0], res.size());
    } else {
        return string((char *)&ptext_buf[0], ptext_buf.size());
    }
}

//TODO: have some helpers that only manipulate unsigned char * and convert in string at the end

static string
reverse(const string & vec)
{
    size_t len = vec.length();
    size_t noBlocks = len /AES_BLOCK_BYTES;

    assert(len == noBlocks * AES_BLOCK_BYTES);
    string rev;
    rev.resize(len);

    for (unsigned int i = 0; i < noBlocks; i++) {
        memcpy(&rev[i * AES_BLOCK_BYTES],
               &vec[(noBlocks-i-1)*AES_BLOCK_BYTES], AES_BLOCK_BYTES);
    }

    return rev;
}

//DID WE DECIDE ON ONE OR TWO KEYS?!
string
encrypt_AES_CMC(const string &ptext, const AES_KEY * enckey)
{
    string firstenc = encrypt_AES_CBC(ptext, enckey, "0");

    string rev = reverse(firstenc);

    return encrypt_AES_CBC(rev, enckey, "0", false);
}

string
decrypt_AES_CMC(const string &ctext, const AES_KEY * deckey)
{
    string firstdec = decrypt_AES_CBC(ctext, deckey, "0", false);

    string reversed = reverse(firstdec);

    return decrypt_AES_CBC(reversed, deckey, "0");
}

