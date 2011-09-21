#pragma once

template<class Hash>
class hmac {
 public:
    hmac(const std::string &key) {
        assert(Hash::blocksize >= Hash::hashsize);

        uint8_t k[Hash::blocksize];
        memset(k, 0, sizeof(k));
        if (key.length() <= Hash::blocksize) {
            memcpy(k, key.data(), key.length());
        } else {
            Hash kh;
            kh.update(key.data(), key.length());
            kh.final(k);
        }

        for (size_t i = 0; i < Hash::blocksize; i++) {
            opad[i] = k[i] ^ 0x5c;
            ipad[i] = k[i] ^ 0x36;
        }

        h.update(ipad, sizeof(ipad));
    }

    void update(const void *data, size_t len) {
        h.update(data, len);
    }

    void final(uint8_t *buf) {
        uint8_t inner[Hash::hashsize];
        h.final(inner);

        Hash outer;
        outer.update(opad, sizeof(opad));
        outer.update(inner, sizeof(inner));
        outer.final(buf);
    }

    std::vector<uint8_t> final() {
        std::vector<uint8_t> v(Hash::hashsize);
        final(&v[0]);
        return v;
    }

    static std::vector<uint8_t> mac(const std::vector<uint8_t> &v, const std::string &key) {
        hmac x(key);
        x.update(&v[0], v.size());
        return x.final();
    }

    static std::vector<uint8_t> mac(const std::string &m, const std::string &key) {
        hmac x(key);
        x.update(m.data(), m.length());
        return x.final();
    }

 private:
    uint8_t opad[Hash::blocksize];
    uint8_t ipad[Hash::blocksize];
    Hash h;
};
