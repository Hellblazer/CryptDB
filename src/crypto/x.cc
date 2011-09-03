#include <assert.h>
#include <vector>
#include <crypto/cbc.hh>
#include <crypto/prng.hh>
#include <crypto/aes.hh>
#include <crypto/blowfish.hh>
#include <util/timer.hh>

using namespace std;

template<class T>
uint64_t
test_block_cipher(T *c, PRNG *u)
{
    auto pt = u->rand_vec<uint8_t>(c->blocksize);
    vector<uint8_t> ct(pt.size()), pt2(pt.size());

    c->block_encrypt(&pt[0], &ct[0]);
    c->block_decrypt(&ct[0], &pt2[0]);
    assert(pt == pt2);

    auto cbc_pt = u->rand_vec<uint8_t>(c->blocksize * 32);
    auto cbc_iv = u->rand_vec<uint8_t>(c->blocksize);
    vector<uint8_t> cbc_ct, cbc_pt2;
    cbc_encrypt(c, cbc_iv, cbc_pt, &cbc_ct);
    cbc_decrypt(c, cbc_iv, cbc_ct, &cbc_pt2);
    assert(cbc_pt == cbc_pt2);

    enum { nperf = 100 * 1000 };
    auto cbc_perf_pt = u->rand_vec<uint8_t>(1024);
    vector<uint8_t> cbc_perf_ct, cbc_perf_pt2;
    timer cbc_perf;
    for (uint i = 0; i < nperf; i++) {
        cbc_encrypt(c, cbc_iv, cbc_perf_pt, &cbc_perf_ct);
        // cbc_decrypt(c, cbc_iv, cbc_perf_ct, &cbc_perf_pt2);
        // assert(cbc_perf_pt == cbc_perf_pt2);
    }

    return cbc_perf_pt.size() * nperf * 1000 * 1000 / cbc_perf.lap();
}

int
main(int ac, char **av)
{
    urandom u;
    cout << u.rand<uint64_t>() << endl;
    cout << u.rand<int64_t>() << endl;

    // AES aes(u.rand_vec<uint8_t>(16));
    // cout << "aes-cbc speed: " << test_block_cipher(&aes, &u) << endl;

    blowfish bf(u.rand_vec<uint8_t>(128));
    cout << "bf-cbc  speed: " << test_block_cipher(&bf, &u) << endl;
}
