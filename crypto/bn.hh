#pragma once

#include <openssl/bn.h>
#include <openssl/crypto.h>

class bignum_ctx {
 public:
    bignum_ctx() { c = BN_CTX_new(); }
    ~bignum_ctx() { BN_CTX_free(c); }
    BN_CTX *ctx() { return c; }

 private:
    BN_CTX *c;
};

class bignum {
 public:
    bignum() {
        BN_init(&b);
    }

    bignum(unsigned long v) {
        BN_init(&b);
        BN_set_word(&b, v);
    }

    bignum(const bignum &other) {
        BN_init(&b);
        assert(BN_copy(&b, other.bn()));
    }

    ~bignum() { BN_free(&b); }

    BIGNUM *bn() { return &b; }
    const BIGNUM *bn() const { return &b; }
    unsigned long word() const {
        unsigned long v = BN_get_word(&b);
        if (v == 0xffffffffL)
            throw std::runtime_error("out of range");
        return v;
    }

#define op(opname, func, args...)                               \
    bignum opname(const bignum &mod) {                          \
        bignum res;                                             \
        assert(1 == func(res.bn(), &b, mod.bn(), ##args));      \
        return res;                                             \
    }

    op(operator+, BN_add)
    op(operator-, BN_sub)
    op(operator%, BN_mod, ctx())
    op(operator*, BN_mul, ctx())
#undef op

#define pred(predname, cmp)                                     \
    bool predname(const bignum &other) {                        \
        return BN_cmp(&b, other.bn()) cmp;                      \
    }

    pred(operator<,  <  0)
    pred(operator<=, <= 0)
    pred(operator>,  >  0)
    pred(operator>=, >= 0)
    pred(operator==, == 0)
#undef pred

 private:
    BIGNUM b;

    static BN_CTX *ctx() {
        static bignum_ctx cx;
        return cx.ctx();
    }
};

static inline std::ostream&
operator<<(std::ostream &out, const bignum &bn)
{
    char *s = BN_bn2dec(bn.bn());
    out << s;
    OPENSSL_free(s);
    return out;
}
