#pragma once

#include <vector>
#include <stdint.h>

using namespace std;

template<class BlockCipher>
void
cbc_encrypt(BlockCipher *c,
            const std::vector<uint8_t> &iv,
            const std::vector<uint8_t> &ptext,
            std::vector<uint8_t> *ctext)
{
    assert(iv.size() == BlockCipher::blocksize);
    assert(ptext.size() % BlockCipher::blocksize == 0);
    ctext->resize(ptext.size());

    for (size_t i = 0; i < ptext.size(); i += BlockCipher::blocksize) {
        uint8_t x[BlockCipher::blocksize];
        for (size_t j = 0; j < BlockCipher::blocksize; j++)
            x[j] = ptext[i+j] ^ ((i == 0) ? iv[j]
                                          : (*ctext)[i+j-BlockCipher::blocksize]);
        c->block_encrypt(x, &(*ctext)[i]);
    }
}

template<class BlockCipher>
void
cbc_decrypt(BlockCipher *c,
            const std::vector<uint8_t> &iv,
            const std::vector<uint8_t> &ctext,
            std::vector<uint8_t> *ptext)
{
    assert(iv.size() == BlockCipher::blocksize);
    assert(ctext.size() % BlockCipher::blocksize == 0);
    ptext->resize(ctext.size());

    for (size_t i = 0; i < ctext.size(); i += BlockCipher::blocksize) {
        uint8_t x[BlockCipher::blocksize];
        c->block_decrypt(&ctext[i], x);
        for (size_t j = 0; j < BlockCipher::blocksize; j++)
            (*ptext)[i+j] = x[j] ^ ((i == 0) ? iv[j]
                                             : ctext[i+j-BlockCipher::blocksize]);
    }
}
