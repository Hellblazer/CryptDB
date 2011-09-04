#include <assert.h>
#include <crypto/ope.hh>
#include <crypto/prng.hh>
#include <crypto/hgd.hh>
#include <crypto/arc4.hh>

using namespace std;
using namespace NTL;

/*
 * A gap is represented by the next integer value _above_ the gap.
 */
static ZZ
domain_gap(const ZZ &ndomain, const ZZ &nrange, const ZZ &rgap, PRNG *prng)
{
    return HGD(rgap, ndomain, nrange-ndomain, prng);
}

template<class CB>
ope_domain_range
OPE::lazy_sample(const ZZ &d_lo, const ZZ &d_hi,
                 const ZZ &r_lo, const ZZ &r_hi,
                 CB go_low, PRNG *prng)
{
    ZZ ndomain = d_hi - d_lo + 1;
    ZZ nrange  = r_hi - r_lo + 1;
    assert(nrange >= ndomain);

    if (ndomain == 1)
        return ope_domain_range(d_lo, r_lo, r_hi);

    ZZ rgap = nrange/2;
    ZZ dgap;

    auto ci = dgap_cache.find(r_lo + rgap);
    if (ci == dgap_cache.end()) {
        dgap = domain_gap(ndomain, nrange, rgap, prng);
        dgap_cache[r_lo + rgap] = dgap;
    } else {
        dgap = ci->second;
    }

    if (go_low(d_lo + dgap, r_lo + rgap))
        return lazy_sample(d_lo, d_lo + dgap - 1, r_lo, r_lo + rgap - 1, go_low, prng);
    else
        return lazy_sample(d_lo + dgap, d_hi, r_lo + rgap, r_hi, go_low, prng);
}

template<class CB>
ope_domain_range
OPE::search(CB go_low)
{
    streamrng<arc4> r(key);
    return lazy_sample(to_ZZ(0), to_ZZ(1) << pbits,
                       to_ZZ(0), to_ZZ(1) << cbits,
                       go_low, &r);
}

ZZ
OPE::encrypt(const ZZ &ptext, int offset)
{
    ope_domain_range dr =
        search([&ptext](const ZZ &d, const ZZ &) { return ptext < d; });

    ZZ nrange = dr.r_hi - dr.r_lo + 1;
    ZZ nrquad = nrange / 4;
    static urandom urand;

    switch (offset) {
    case -1:
        return dr.r_lo + urand.rand_zz_mod(nrquad);
    case 0:
        return dr.r_lo + nrquad + urand.rand_zz_mod(nrquad * 2);
    case 1:
        return dr.r_lo + nrquad * 3 + urand.rand_zz_mod(nrquad);
    default:
        assert(0);
    }
}

ZZ
OPE::decrypt(const ZZ &ctext)
{
    ope_domain_range dr =
        search([&ctext](const ZZ &, const ZZ &r) { return ctext < r; });
    return dr.d;
}
