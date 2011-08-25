/*
 * BasicCrypto.cc
 *
 *
 */

#include "BasicCrypto.h"


AES_KEY *
get_AES_KEY(const string &key)
{
    AES_KEY * aes_key = new AES_KEY();

    if (AES_set_encrypt_key((const uint8_t*) key.c_str(), AES_KEY_SIZE,
                            aes_key) <0) {
        myassert(false, "problem with AES set encrypt ");
    }

    return aes_key;

}

AES_KEY *
get_AES_enc_key(const string &key)
{
    return get_AES_KEY(key);
}


AES_KEY *
get_AES_dec_key(const string &key)
{
    AES_KEY * aes_key = new AES_KEY();

    if (AES_set_decrypt_key((const uint8_t*) key.c_str(), AES_KEY_SIZE,
                            aes_key) <0) {
        myassert(false, "problem with AES set encrypt ");
    }

    return aes_key;

}



static unsigned int
getBlocks(unsigned int unit, unsigned int len) {
    unsigned int blocks = len / unit;
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

static unsigned char *
getIVec(string salt) {
    unsigned char * ivec = new unsigned char[AES_BLOCK_BYTES];

    memcpy(ivec, salt.data(), min(salt.length(), AES_BLOCK_BYTES));

    return ivec;
}

unsigned char *  pad(unsigned char * data, unsigned int len, unsigned int unit, unsigned int & paddedLen) {

    assert_s(unit < 256, "pad does not work for padding unit more than 256 bytes");
    size_t blocks = getBlocks(unit, len);
    size_t multipleLen = blocks * unit;
    size_t padding;
    if (multipleLen == len) {
        padding = unit;
    } else {
        padding = multipleLen - len;
    }
    paddedLen = len + padding;

    cerr << "length of padding " << padding << " length of padded data " << paddedLen << "\n";

    unsigned char * res = new unsigned char[paddedLen];
    memset(res, 0, paddedLen);
    res[paddedLen-1] = (char)padding;

    memcpy(res, data, len);

    return res;

}

unsigned char * unpad(unsigned char * data, unsigned int len, unsigned int & actualLen) {
    cerr << "padding to remove " << (int)data[len-1] << "\n";
    actualLen = len - (int)data[len-1];
    unsigned char * res = new unsigned char[actualLen];
    memcpy(res, data, actualLen);
    return res;
}


string
encrypt_AES_CBC(const string &ptext, const AES_KEY * enckey, string salt, bool dopad) {

    //TODO: separately for numbers to avoid need for padding

    unsigned int paddedLen = 0;

    const unsigned char * ptext_buf;
    if (dopad) {
        ptext_buf = pad((unsigned char *)ptext.data(), ptext.length(), AES_BLOCK_BYTES, paddedLen);
        cerr << "padded data is " << stringToByteInts(string((char *)ptext_buf, paddedLen)) << "\n";
    } else {
        ptext_buf = (const unsigned char *)ptext.data();
        paddedLen = ptext.length();
    }
    unsigned char * ctext_buf = new unsigned char[paddedLen];

    unsigned char * ivec = getIVec(salt);

    AES_cbc_encrypt(ptext_buf, ctext_buf, paddedLen , enckey, ivec, AES_ENCRYPT);

    cerr << "encrypted data is " << stringToByteInts(string((char *)ctext_buf, paddedLen)) << '\n';
    //free(ivec);

    string result = string((char *)ctext_buf, paddedLen);

    free(ctext_buf);

    return result;
}

string
decrypt_AES_CBC(const string &ctext, const AES_KEY * deckey, string salt, bool dounpad) {
    unsigned int ctext_len = ctext.length();

    unsigned char * ptext_buf = new unsigned char[ctext_len];

    unsigned char * ivec = getIVec(salt);

    AES_cbc_encrypt((const unsigned char *)ctext.data(), ptext_buf, ctext_len , deckey, ivec, AES_DECRYPT);

    cerr << "padded dec data is " << stringToByteInts(string((char *)ptext_buf, ctext_len)) << "\n";

    unsigned int ptext_len;

    string result;
    if (dounpad) {
        unsigned char * res = unpad(ptext_buf, ctext_len, ptext_len);

        //free(ivec);
        cerr << "unpadded dec data is " << stringToByteInts(string((char * )res, ptext_len)) << "\n";
        result = string((char *)res, ptext_len);

        free(res);

    } else {
        result = string((char *)ptext_buf, ctext_len);

    }
    free(ptext_buf);
    return result;

}

//TODO: have some helpers that only manipulate unsigned char * and convert in string at the end

static string
reverse(const string & vec) {
    unsigned int len = vec.length();
    unsigned int noBlocks = len /AES_BLOCK_BYTES;
    const char * data = vec.data();

    char * reversed = new char[len];

    for (unsigned int i = 0; i < noBlocks; i++) {
        memcpy(reversed + (i * AES_BLOCK_BYTES), data + ((noBlocks-i-1)*AES_BLOCK_BYTES), AES_BLOCK_BYTES);
    }

    string rev = string((char *) reversed, len);
    free(reversed);

    return rev;
}
//DID WE DECIDE ON ONE OR TWO KEYS?!
string
encrypt_AES_CMC(const string &ptext, const AES_KEY * enckey) {
    string firstenc = encrypt_AES_CBC(ptext, enckey, "0");

    string rev = reverse(firstenc);

    return encrypt_AES_CBC(rev, enckey, "0", false);

}

string
decrypt_AES_CMC(const string &ctext, const AES_KEY * deckey) {
    string firstdec = decrypt_AES_CBC(ctext, deckey, "0", false);

    string reversed = reverse(firstdec);

    return decrypt_AES_CBC(reversed, deckey, "0");

}
