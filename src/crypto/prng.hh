#pragma once

#include <string>
#include <fstream>
#include <util/errstream.hh>

class PRNG {
 public:
    template<class T>
    T rand() {
        std::string s = rand_bytes(sizeof(T));
        return *(T*) s.data();
    }

    virtual ~PRNG() {}
    virtual std::string rand_bytes(size_t nbytes) = 0;
    virtual void seed(const std::string &rnd) {
        thrower() << "seed not implemented";
    }
};

class urandom : public PRNG {
 public:
    urandom();
    virtual ~urandom() {}
    virtual std::string rand_bytes(size_t nbytes);
    virtual void seed(const std::string &rnd);

 private:
    std::fstream f;
};

template<class StreamCipher>
class streamrng : public PRNG {
 public:
    streamrng(const std::string &key) : c(key) {}
    virtual std::string rand_bytes(size_t nbytes) {
        std::string res;
        for (size_t i = 0; i < nbytes; i++)
            res += (char) c.getbyte();
        return res;
    }

 private:
    StreamCipher c;
};
