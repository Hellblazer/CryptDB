#pragma once

#include <string>
#include <cstring>

template<class BlockCipher>
void
cmc_encrypt(BlockCipher *c,
            const std::vector<uint8_t> &ptext,
            std::vector<uint8_t> *ctext)
{
    assert(ptext.size() % BlockCipher::blocksize == 0);
    ctext->resize(ptext.size());
    uint8_t x[BlockCipher::blocksize];

    memset(x, 0, BlockCipher::blocksize);
    for (size_t i = 0; i < ptext.size(); i += BlockCipher::blocksize) {
        uint8_t y[BlockCipher::blocksize];
        for (size_t j = 0; j < BlockCipher::blocksize; j++)
            y[j] = ptext[i+j] ^ x[j];

        c->block_encrypt(y, &(*ctext)[i]);
        memcpy(x, &(*ctext)[i], BlockCipher::blocksize);
    }

    uint8_t m[BlockCipher::blocksize];
    uint8_t carry = 0;
    for (size_t j = BlockCipher::blocksize; j != 0; j--) {
        uint16_t a = (*ctext)[j - 1] ^
                     (*ctext)[j - 1 + ptext.size() - BlockCipher::blocksize];
        m[j] = carry | (uint8_t) (a << 1);
        carry = a >> 7;
    }
    m[BlockCipher::blocksize-1] |= carry;

    for (size_t i = 0; i < ptext.size(); i += BlockCipher::blocksize) {
        for (size_t j = 0; j < BlockCipher::blocksize; j++)
            (*ctext)[i+j] ^= m[j];
    }

    memset(x, 0, BlockCipher::blocksize);
    for (size_t i = ptext.size(); i != 0; i -= BlockCipher::blocksize) {
        uint8_t y[BlockCipher::blocksize];
        c->block_encrypt(&(*ctext)[i - BlockCipher::blocksize], y);

        uint8_t z[BlockCipher::blocksize];
        for (size_t j = 0; j < BlockCipher::blocksize; j++)
            z[j] = y[j] ^ x[j];

        memcpy(x, &(*ctext)[i - BlockCipher::blocksize], BlockCipher::blocksize);
        memcpy(&(*ctext)[i - BlockCipher::blocksize], z, BlockCipher::blocksize);
    }
}

template<class BlockCipher>
void
cmc_decrypt(BlockCipher *c,
            const std::vector<uint8_t> &ctext,
            std::vector<uint8_t> *ptext)
{
    assert(ctext.size() % BlockCipher::blocksize == 0);
    ptext->resize(ctext.size());
    uint8_t x[BlockCipher::blocksize];

    memset(x, 0, BlockCipher::blocksize);
    for (size_t i = ctext.size(); i != 0; i -= BlockCipher::blocksize) {
        uint8_t y[BlockCipher::blocksize];
        for (size_t j = 0; j < BlockCipher::blocksize; j++)
            y[j] = ctext[i - BlockCipher::blocksize + j] ^ x[j];

        c->block_decrypt(y, &(*ptext)[i - BlockCipher::blocksize]);
        memcpy(x, &(*ptext)[i - BlockCipher::blocksize], BlockCipher::blocksize);
    }

    uint8_t m[BlockCipher::blocksize];
    uint8_t carry = 0;
    for (size_t j = BlockCipher::blocksize; j != 0; j--) {
        uint16_t a = (*ptext)[j - 1] ^
                     (*ptext)[j - 1 + ctext.size() - BlockCipher::blocksize];
        m[j] = carry | (uint8_t) (a << 1);
        carry = a >> 7;
    }

    m[BlockCipher::blocksize-1] |= carry;
    for (size_t i = 0; i < ctext.size(); i += BlockCipher::blocksize) {
        for (size_t j = 0; j < BlockCipher::blocksize; j++)
            (*ptext)[i+j] ^= m[j];
    }

    memset(x, 0, BlockCipher::blocksize);
    for (size_t i = 0; i < ctext.size(); i += BlockCipher::blocksize) {
        uint8_t y[BlockCipher::blocksize];
        c->block_decrypt(&(*ptext)[i], y);

        uint8_t z[BlockCipher::blocksize];
        for (size_t j = 0; j < BlockCipher::blocksize; j++)
            z[j] = y[j] ^ x[j];

        memcpy(x, &(*ptext)[i], BlockCipher::blocksize);
        memcpy(&(*ptext)[i], z, BlockCipher::blocksize);
    }
}
