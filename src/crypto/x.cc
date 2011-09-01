#include <assert.h>
#include <crypto/cbc.hh>
#include <crypto/prng.hh>
#include <crypto/aes.hh>

using namespace std;

int
main(int ac, char **av)
{
    urandom u;
    cout << u.rand<uint64_t>() << endl;
    cout << u.rand<int64_t>() << endl;

    AES aes(u.rand_bytes(32));
    string x = u.rand_bytes(aes.blocksize);
    assert(x == aes.block_decrypt(aes.block_encrypt(x)));
    assert(x == aes.block_encrypt(aes.block_decrypt(x)));

    string y = u.rand_bytes(aes.blocksize * 32);
    string iv = u.rand_bytes(aes.blocksize);
    assert(y == cbc_decrypt(&aes, iv, cbc_encrypt(&aes, iv, y)));
    assert(y == cbc_encrypt(&aes, iv, cbc_decrypt(&aes, iv, y)));
}
