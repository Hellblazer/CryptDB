#include <assert.h>
#include <vector>
#include <crypto/cbc.hh>
#include <crypto/prng.hh>
#include <crypto/aes.hh>
#include <util/scopedperf.hh>

using namespace std;

static tod_ctr tod_c;
static auto cg = ctrgroup(&tod_c);

void
foo(AES *a, urandom *u, vector<uint8_t> *res)
{
    auto pt = u->rand_vec<uint8_t>(16);
    auto iv = u->rand_vec<uint8_t>(16);
    cbc_encrypt(a, iv, pt, res);
}

int
main(int ac, char **av)
{
    urandom u;
    cout << u.rand<uint64_t>() << endl;
    cout << u.rand<int64_t>() << endl;

    AES aes(u.rand_vec<uint8_t>(16));
    auto x0 = u.rand_vec<uint8_t>(aes.blocksize);
    vector<uint8_t> x1(x0.size()), x2(x0.size());
    aes.block_encrypt(&x0[0], &x1[0]);
    aes.block_decrypt(&x1[0], &x2[0]);
    assert(x0 == x2);

    auto y0 = u.rand_vec<uint8_t>(aes.blocksize * 32);
    auto iv = u.rand_vec<uint8_t>(aes.blocksize);
    vector<uint8_t> y1, y2;
    cbc_encrypt(&aes, iv, y0, &y1);
    cbc_decrypt(&aes, iv, y1, &y2);
    assert(y0 == y2);

    auto z0 = u.rand_vec<uint8_t>(1024);
    vector<uint8_t> z1, z2;
    auto cbc_sum = perfsum<always_enabled>("aes cbc (1024b, 300mb)", &cg);
    auto cbc_perf = perf_region(&cbc_sum);
    for (uint i = 0; i < 300 * 1000; i++) {
        cbc_encrypt(&aes, iv, z0, &z1);
        // cbc_decrypt(&aes, iv, z1, &z2);
        // assert(z0 == z2);
        cbc_perf.lap();
    }

    foo(&aes, &u, &z1);

    perfsum_base::printall(30);
}
