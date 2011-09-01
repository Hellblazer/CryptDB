#include <assert.h>
#include <crypto/cbc.hh>
#include <crypto/prng.hh>
#include <crypto/aes.hh>
#include <util/scopedperf.hh>

using namespace std;

static tod_ctr tod_c;
static auto cg = ctrgroup(&tod_c);

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

    string xx = u.rand_bytes(1024);
    auto cbc_sum = perfsum<always_enabled>("aes cbc (1024b, 100mb)", &cg);
    auto cbc_perf = perf_region(&cbc_sum);
    for (uint i = 0; i < 100 * 1000; i++) {
        string yy = cbc_encrypt(&aes, iv, xx);
        // assert(cbc_decrypt(&aes, iv, yy) == xx);
        cbc_perf.lap();
    }

    perfsum_base::printall(30);
}
