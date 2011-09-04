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

enum class target_type { domain, range };

class domain_range {
 public:
    domain_range(const ZZ &d_arg, const ZZ &r_lo_arg, const ZZ &r_hi_arg)
        : d(d_arg), r_lo(r_lo_arg), r_hi(r_hi_arg) {}

    ZZ d;
    ZZ r_lo;
    ZZ r_hi;
};

static domain_range
lazy_sample(const ZZ &d_lo, const ZZ &d_hi,
            const ZZ &r_lo, const ZZ &r_hi,
            const ZZ &target, target_type tt,
            PRNG *prng)
{
    ZZ ndomain = d_hi - d_lo + 1;
    ZZ nrange  = r_hi - r_lo + 1;

    assert(nrange >= ndomain);
    if (tt == target_type::domain)
        assert(target >= d_lo && target <= d_hi);
    else
        assert(target >= r_lo && target <= r_hi);

    if (ndomain == 1)
        return domain_range(d_lo, r_lo, r_hi);

    ZZ rgap = nrange/2;
    ZZ dgap = domain_gap(ndomain, nrange, rgap, prng);
    bool go_low = (tt == target_type::domain) ? (target < d_lo + dgap) : (target < r_lo + rgap);
    if (go_low)
        return lazy_sample(d_lo, d_lo + dgap - 1, r_lo, r_lo + rgap - 1, target, tt, prng);
    else
        return lazy_sample(d_lo + dgap, d_hi, r_lo + rgap, r_hi, target, tt, prng);
}

ZZ
OPE::encrypt(const ZZ &ptext)
{
    streamrng<arc4> r(key);
    domain_range dr = lazy_sample(to_ZZ(0), to_ZZ(1) << pbits,
                                  to_ZZ(0), to_ZZ(1) << cbits,
                                  ptext, target_type::domain, &r);
    return dr.r_lo;
}

ZZ
OPE::decrypt(const ZZ &ctext)
{
    streamrng<arc4> r(key);
    domain_range dr = lazy_sample(to_ZZ(0), to_ZZ(1) << pbits,
                                  to_ZZ(0), to_ZZ(1) << cbits,
                                  ctext, target_type::range, &r);
    return dr.d;
}
