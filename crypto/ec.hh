#pragma once

#include <openssl/ec.h>
#include <openssl/bn.h>

class ec_point {
 public:
    ec_point(const EC_GROUP *group) {
        g = group;
        p = EC_POINT_new(g);
    }

    ec_point(const ec_point &other) {
        g = other.g;
        p = EC_POINT_dup(other.p, g);
    }

    ~ec_point() {
        EC_POINT_free(p);
    }

    ec_point operator*(const bignum &n) {
        bignum zero(0);
        ec_point res(g);
        assert(EC_POINT_mul(g, res.p(), zero.bn(),
                            p, n.bn(), bignum_ctx::the_ctx()));
        return res;
    }

    EC_POINT *p() { return p; }

 private:
    EC_POINT *p;
    EC_GROUP *g;
};
