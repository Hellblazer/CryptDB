#pragma once

#include <string>

template<class BlockCipher>
std::string
cbc_encrypt(BlockCipher *c, const std::string &iv, const std::string &plaintext)
{
    assert(plaintext.size() % BlockCipher::blocksize == 0);
    std::string res;
    std::string pc = iv;

    for (size_t i = 0; i < plaintext.size(); i += BlockCipher::blocksize) {
        std::string x;
        for (size_t j = 0; j < BlockCipher::blocksize; j++)
            x += (plaintext[i+j] ^ pc[j]);
        pc = c->block_encrypt(x);
        res += pc;
    }

    return res;
}

template<class BlockCipher>
std::string
cbc_decrypt(BlockCipher *c, const std::string &iv, const std::string &ciphertext)
{
    assert(ciphertext.size() % BlockCipher::blocksize == 0);
    std::string res;
    std::string pc = iv;

    for (size_t i = 0; i < ciphertext.size(); i += BlockCipher::blocksize) {
        std::string nc = ciphertext.substr(i, BlockCipher::blocksize);
        std::string x = c->block_decrypt(nc);
        std::string p;
        for (size_t j = 0; j < BlockCipher::blocksize; j++)
            p += (x[j] ^ pc[j]);
        res += p;
        pc = nc;
    }

    return res;
}
