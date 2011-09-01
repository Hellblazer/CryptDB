#include <assert.h>
#include <crypto/aes.hh>

using namespace std;

AES::AES(const string &key)
{
    assert(key.size() == 16 || key.size() == 24 || key.size() == 32);
    AES_set_encrypt_key((const uint8_t *) key.data(), key.size(), &enc);
    AES_set_decrypt_key((const uint8_t *) key.data(), key.size(), &dec);
}

string
AES::block_encrypt(const string &plaintext)
{
    unsigned char buf[16];
    assert(plaintext.size() == 16);
    AES_encrypt((const uint8_t *) plaintext.data(), buf, &enc);
    return string((char *) buf, sizeof(buf));
}

string
AES::block_decrypt(const string &ciphertext)
{
    unsigned char buf[16];
    assert(ciphertext.size() == 16);
    AES_decrypt((const uint8_t *) ciphertext.data(), buf, &dec);
    return string((char *) buf, sizeof(buf));
}
