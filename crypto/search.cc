#include <algorithm>
#include <crypto/search.hh>
#include <crypto/sha.hh>
#include <crypto/hmac.hh>
#include <crypto/prng.hh>

using namespace std;

static bool
vector_compare(const vector<uint8_t> &a, const vector<uint8_t> &b)
{
    if (a.size() != b.size())
        return a.size() - b.size();
    for (size_t i = 0; i < a.size(); i++)
        if (a[i] != b[i])
            return a[i] - b[i];
    return 0;
}

static vector<uint8_t>
xor_pad(const vector<uint8_t> &word_key, size_t csize)
{
    auto v = sha256::hash(word_key);
    assert(v.size() >= csize);
    v.resize(csize);
    return v;
}

bool
search::match(const vector<uint8_t> &ctext,
              const vector<uint8_t> &word_key)
{
    assert(ctext.size() == csize);
    vector<uint8_t> cx;

    auto xorpad = xor_pad(word_key, csize);
    for (size_t i = 0; i < csize; i++)
        cx.push_back(ctext[i] ^ xorpad[i]);

    vector<uint8_t> salt = cx;
    salt.resize(csize/2);

    vector<uint8_t> cf(cx.begin() + csize/2, cx.end());
    auto f = hmac<sha1>::mac(salt, word_key);
    f.resize((csize + 1) / 2);

    return vector_compare(f, cf) == 0;
}

bool
search::match(const vector<vector<uint8_t>> &ctexts,
              const vector<uint8_t> &word_key)
{
    for (auto &c: ctexts)
        if (match(c, word_key))
            return true;
    return false;
}

vector<uint8_t>
search_priv::transform(const string &word)
{
    auto word_key = wordkey(word);

    urandom r;
    auto salt = r.rand_vec<uint8_t>(csize / 2);

    auto f = hmac<sha1>::mac(salt, word_key);
    f.resize((csize + 1) / 2);

    vector<uint8_t> x;
    x.insert(x.end(), salt.begin(), salt.end());
    x.insert(x.end(), f.begin(), f.end());

    auto xorpad = xor_pad(word_key, csize);
    for (size_t i = 0; i < csize; i++)
        x[i] ^= xorpad[i];

    return x;
}

vector<vector<uint8_t>>
search_priv::transform(const vector<string> &words)
{
    vector<vector<uint8_t>> res;
    for (auto &w: words)
        res.push_back(transform(w));
    sort(res.begin(), res.end(), vector_compare);
    return res;
}

vector<uint8_t>
search_priv::wordkey(const string &word)
{
    return hmac<sha1>::mac(word, master_key);
}
