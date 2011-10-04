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

bool
search::match(const vector<uint8_t> &ctext,
              const vector<uint8_t> &wordkey)
{
    vector<uint8_t> salt = ctext;
    salt.resize(csize/2);

    vector<uint8_t> cf(ctext.begin() + csize/2, ctext.end());
    auto f = hmac<sha1>::mac(salt, wordkey);
    f.resize((csize + 1) / 2);

    return vector_compare(f, cf) == 0;
}

bool
search::match(const vector<vector<uint8_t>> &ctexts,
              const vector<uint8_t> &wordkey)
{
    for (auto &c: ctexts)
        if (match(c, wordkey))
            return true;
    return false;
}

vector<uint8_t>
search_priv::transform(const string &word)
{
    urandom r;
    auto salt = r.rand_vec<uint8_t>(csize / 2);

    auto f = hmac<sha1>::mac(salt, wordkey(word));
    f.resize((csize + 1) / 2);

    vector<uint8_t> x;
    x.insert(x.end(), salt.begin(), salt.end());
    x.insert(x.end(), f.begin(), f.end());
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
