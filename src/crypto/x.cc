#include <assert.h>
#include <vector>
#include <crypto/cbc.hh>
#include <crypto/cmc.hh>
#include <crypto/prng.hh>
#include <crypto/aes.hh>
#include <crypto/blowfish.hh>
#include <crypto/ope.hh>
#include <util/timer.hh>
#include <NTL/ZZ.h>
#include <NTL/RR.h>

using namespace std;
using namespace NTL;

template<class T>
void
test_block_cipher(T *c, PRNG *u, const std::string &cname)
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

    cmc_encrypt(c, cbc_pt, &cbc_ct);
    cmc_decrypt(c, cbc_ct, &cbc_pt2);
    assert(cbc_pt == cbc_pt2);

    enum { nperf = 100 * 1000 };
    auto cbc_perf_pt = u->rand_vec<uint8_t>(1024);
    auto cbc_perf_iv = u->rand_vec<uint8_t>(c->blocksize);
    vector<uint8_t> cbc_perf_ct, cbc_perf_pt2;
    timer cbc_perf;
    for (uint i = 0; i < nperf; i++) {
        cbc_encrypt(c, cbc_perf_iv, cbc_perf_pt, &cbc_perf_ct);
        if (i == 0) {
            cbc_decrypt(c, cbc_perf_iv, cbc_perf_ct, &cbc_perf_pt2);
            assert(cbc_perf_pt == cbc_perf_pt2);
        }
    }

    cout << cname << "-cbc speed: "
         << cbc_perf_pt.size() * nperf * 1000 * 1000 / cbc_perf.lap() << endl;

    timer cmc_perf;
    for (uint i = 0; i < nperf; i++) {
        cmc_encrypt(c, cbc_perf_pt, &cbc_perf_ct);
        if (i == 0) {
            cmc_decrypt(c, cbc_perf_ct, &cbc_perf_pt2);
            assert(cbc_perf_pt == cbc_perf_pt2);
        }
    }

    cout << cname << "-cmc speed: "
         << cbc_perf_pt.size() * nperf * 1000 * 1000 / cmc_perf.lap() << endl;
}

static void
test_ope(int pbits, int cbits)
{
    urandom u;
    OPE o("hello world", pbits, cbits);
    RR maxerr = to_RR(0);

    for (uint i = 1; i < 100; i++) {
        ZZ pt = to_ZZ(u.rand<uint32_t>());
        ZZ ct = o.encrypt(pt);
        ZZ pt2 = o.decrypt(ct);
        assert(pt2 == pt);
        // cout << pt << " -> " << o.encrypt(pt, -1) << "/" << ct << "/" << o.encrypt(pt, 1) << " -> " << pt2 << endl;

        ZZ guess = ct / (to_ZZ(1) << (cbits-pbits));
        RR error = abs(to_RR(guess) / to_RR(pt) - 1);
        maxerr = max(error, maxerr);
        // cout << "pt guess is " << error << " off" << endl;
    }

    cout << "max error (" << pbits << ", " << cbits << "): " << maxerr << endl;
}

int
main(int ac, char **av)
{
    urandom u;
    cout << u.rand<uint64_t>() << endl;
    cout << u.rand<int64_t>() << endl;

    AES aes128(u.rand_vec<uint8_t>(16));
    test_block_cipher(&aes128, &u, "aes-128");

    AES aes256(u.rand_vec<uint8_t>(32));
    test_block_cipher(&aes256, &u, "aes-256");

    blowfish bf(u.rand_vec<uint8_t>(128));
    test_block_cipher(&bf, &u, "blowfish");

    test_ope(32, 64);
    test_ope(32, 128);
}
