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

static ZZ
lazy_sample(const ZZ &ndomain, const ZZ &nrange, const ZZ &m, PRNG *prng)
{
    assert(nrange >= ndomain);
    assert(m >= 0 && m < ndomain);

    if (ndomain == 1) {
        return to_ZZ(0);   /* should randomize within nrange */
    }

    ZZ rgap = nrange/2;
    ZZ dgap = domain_gap(ndomain, nrange, rgap, prng);
    if (m < dgap)
        return lazy_sample(dgap, rgap, m, prng);
    else
        return rgap + lazy_sample(ndomain-dgap, nrange-rgap, m-dgap, prng);
}

static ZZ
lazy_sample_inv(const ZZ &ndomain, const ZZ &nrange, const ZZ &c, PRNG *prng)
{
    assert(nrange >= ndomain);
    assert(c >= 0 && c < nrange);

    if (ndomain == 1) {
        return to_ZZ(0);
    }

    ZZ rgap = nrange/2;
    ZZ dgap = domain_gap(ndomain, nrange, rgap, prng);
    if (c < rgap)
        return lazy_sample_inv(dgap, rgap, c, prng);
    else
        return dgap + lazy_sample_inv(ndomain-dgap, nrange-rgap, c-rgap, prng);
}

ZZ
OPE::encrypt(const ZZ &ptext)
{
    streamrng<arc4> r(key);
    return lazy_sample(to_ZZ(1) << pbits, to_ZZ(1) << cbits, ptext, &r);
}

ZZ
OPE::decrypt(const ZZ &ctext)
{
    streamrng<arc4> r(key);
    return lazy_sample_inv(to_ZZ(1) << pbits, to_ZZ(1) << cbits, ctext, &r);
}
