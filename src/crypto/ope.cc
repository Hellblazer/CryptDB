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

    /*
     * XXX bug: the arc4 PRNG changes in different ways depending on whether
     * we find dgap in the cache or not.  One solution may be to start a fresh
     * PRNG for each call to lazy_sample(); a cheaper-to-initialize PRNG, e.g.
     * something based on AES, may be a good plan then.
     */

    auto ci = dgap_cache.find(r_lo + rgap);
    if (ci == dgap_cache.end()) {
        dgap = domain_gap(ndomain, nrange, rgap, prng);

        /*
         * XXX for high bits, we are fighting against the law of large numbers,
         * because dgap (the number of marked balls out of a large rgap sample)
         * will be very near to the well-known proportion of marked balls (i.e.,
         * ndomain vs nrange).  Perhaps we need to add extra holes in the range
         * that are not HGD-based, for each level of recursion.  For far x and y,
         * the value of E(x)-E(y) would include not only HGD (statistically
         * predictable), but also some non-converging randomness.  This could
         * fit nicely with the window-one-wayness notion of OPE security from
         * Boldyerva's crypto 2011 paper.
         */

        /*
         * XXX check that the ranges on either side of rgap are at least as large
         * as the domain ranges on either side of dgap.  If not, adjust dgap to
         * ensure that every plaintext has a ciphertext.  (The other option is an
         * encryption scheme that cannot encrypt certain plaintexts..)
         */
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

    /*
     * XXX support a flag (in constructor?) for deterministic vs.
     * randomized OPE mode.  We still need deterministic OPE mode
     * for multi-key sorting (in which cases equality at higher
     * levels matters).
     */

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
