#include <crypto/paillier.hh>
#include <sstream>

using namespace std;
using namespace NTL;

static ZZ
L(const ZZ &u, const ZZ &n)
{
    return (u - 1) / n;
}

static ZZ
Lfast(const ZZ &u, const ZZ &ninv, const ZZ &two_n, const ZZ &n)
{
    return (((u - 1) * ninv) % two_n) % n;
}

static ZZ
LCM(const ZZ &a, const ZZ &b)
{
    return (a * b) / GCD(a, b);
}

Paillier_privkey::Paillier_privkey(uint nbits, uint abits)
{
    ZZ n;

    do {
        if (abits) {
            a = RandomPrime_ZZ(abits);

            ZZ cp = RandomLen_ZZ(nbits/2-abits);
            ZZ cq = RandomLen_ZZ(nbits/2-abits);

            p = a * cp + 1;
            while (!ProbPrime(p))
                p += a;

            q = a * cq + 1;
            while (!ProbPrime(q))
                q += a;
        } else {
            a = 0;
            p = RandomPrime_ZZ(nbits/2);
            q = RandomPrime_ZZ(nbits/2);
        }
        n = p * q;
    } while ((NumBits(n) != nbits) || p == q);

    if (p > q)
        swap(p, q);

    ZZ lambda = LCM(p-1, q-1);

    if (abits) {
        g = PowerMod(to_ZZ(2), lambda / a, n);
    } else {
        g = 1;
        do {
            g++;
        } while (GCD(L(PowerMod(g, lambda, n*n), n), n) != to_ZZ(1));
    }
}

Paillier_privkey::Paillier_privkey(const string &rep)
{
    stringstream ss(rep);
    ss >> p >> q >> g >> a;
}

string
Paillier_privkey::serialize() const
{
    stringstream ss;
    ss << p << " " << q << " " << g << " " << a;
    return ss.str();
}

Paillier::Paillier(const Paillier_privkey &karg)
    : k(karg)
{
    n  = k.p * k.q;
    p2 = k.p * k.p;
    q2 = k.q * k.q;
    n2 = n * n;

    nbits = NumBits(n);
    fast = (k.a != 0);

    two_p = power(to_ZZ(2), NumBits(k.p));
    two_q = power(to_ZZ(2), NumBits(k.q));

    pinv = InvMod(k.p, two_p);
    qinv = InvMod(k.q, two_q);

    hp = InvMod(Lfast(PowerMod(k.g % p2, fast ? k.a : (k.p-1), p2),
                      pinv, two_p, k.p), k.p);
    hq = InvMod(Lfast(PowerMod(k.g % q2, fast ? k.a : (k.q-1), q2),
                      qinv, two_q, k.q), k.q);
}

void
Paillier::rand_gen(size_t niter, size_t nmax)
{
    if (rqueue.size() >= nmax)
        niter = 0;
    else
        niter = min(niter, nmax - rqueue.size());

    for (uint i = 0; i < niter; i++) {
        ZZ r = RandomLen_ZZ(nbits) % n;
        ZZ rn = PowerMod(k.g, n*r, n2);
        rqueue.push_back(rn);
    }
}

ZZ
Paillier::encrypt(const ZZ &plaintext)
{
    auto i = rqueue.begin();
    if (i != rqueue.end()) {
        ZZ rn = *i;
        rqueue.pop_front();

        return (PowerMod(k.g, plaintext, n2) * rn) % n2;
    } else {
        ZZ r = RandomLen_ZZ(nbits) % n;
        return PowerMod(k.g, plaintext + n*r, n2);
    }
}

ZZ
Paillier::decrypt(const ZZ &ciphertext) const
{
    ZZ mp = (Lfast(PowerMod(ciphertext % p2, fast ? k.a : (k.p-1), p2),
                   pinv, two_p, k.p) * hp) % k.p;
    ZZ mq = (Lfast(PowerMod(ciphertext % q2, fast ? k.a : (k.q-1), q2),
                   qinv, two_q, k.q) * hq) % k.q;

    ZZ m, pq;
    pq = 1;
    CRT(m, pq, mp, k.p);
    CRT(m, pq, mq, k.q);

    return m;
}
