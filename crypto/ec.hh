#pragma once

#include <openssl/ec.h>
#include <openssl/bn.h>

class ec_point {
 public:
    ec_point(const EC_GROUP *group) {
        gr = group;
        pt = EC_POINT_new(gr);
    }

    ec_point(const ec_point &other) {
        gr = other.gr;
        pt = EC_POINT_dup(other.pt, gr);
    }

    ~ec_point() {
        EC_POINT_free(pt);
    }

    ec_point operator*(const bignum &n) const {
        bignum zero(0);
        ec_point res(gr);
        assert(EC_POINT_mul(gr, res.p(), zero.bn(),
                            pt, n.bn(), bignum_ctx::the_ctx()));
        return res;
    }

    EC_POINT *p() { return pt; }

 private:
    EC_POINT *pt;
    const EC_GROUP *gr;
};
