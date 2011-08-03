/*
 * ECJoin.cpp
 *
 */

#include "ECJoin.h"



static string
bn2str(BIGNUM * bn) {
	unsigned char * tov = new unsigned char[256];
	int len = BN_bn2bin(bn, tov);

	assert_s(len, "cannot convert from bn to binary ");

	string res = "";

	for (int i = 0 ; i < len ; i++) {
		res = res + StringFromVal(tov[i]) + " ";
	}
	return res;
}

static EC_POINT *
my_EC_POINT_new(EC_GROUP * group) {

    EC_POINT* point = EC_POINT_new(group);
    assert_s(point, "could not create point");
    return point;

}

static BIGNUM *
my_BN_new() {

    BIGNUM* num = BN_new();
    assert_s(num, "could not create BIGNUM");
    return num;

}

EC_POINT *
ECJoin::randomPoint() {
    cerr << "before new point \n";
    EC_POINT * point = my_EC_POINT_new(group);

    cerr << "after new point \n";

    BIGNUM *x = my_BN_new(), *y = my_BN_new(), * rem = my_BN_new();

    bool found = false;

    while (!found) {
    	cerr << "here order is " << bn2str(order) << "\n";
        BN_rand_range(x, order);
       //need to take the mod because BN_rand_range does not work as expected
       // BN_mod(rem, x, order, NULL);
        //x = rem;
        cerr << "here x is " << bn2str(x) << "\n";

       // cerr << "val is " << val <<"\n";
       // cerr << group->meth->point_set_compressed_coordinates << " \n";
        //cerr << (point->meth != group->meth) << "\n";
        if (EC_POINT_set_compressed_coordinates_GFp(group, point, x, 1, NULL)) {
            assert_s(EC_POINT_get_affine_coordinates_GFp(group, point, x, y, NULL),"issue getting coordinates");

            if(BN_is_zero(x) || BN_is_zero(y)) {
                found = false;
                continue;
            }

            if (EC_POINT_is_on_curve(group, point, NULL)) {
                cerr << "found \n";
                found = true;
            } else {
                cerr << "not on curve; try again \n";
            }
        } else {
            cerr << "bad random point; try again \n";
        }
    }

    BN_free(x);
    BN_free(y);
    BN_free(rem);
    return point;
}


ECJoin::ECJoin()
{

    group = EC_GROUP_new_by_curve_name(NID);
    assert_s(group, "issue creating new curve");

    order = my_BN_new();

    assert_s(EC_GROUP_get_order(group, order, NULL), "failed to retrieve the order");

    cerr << "order is " << bn2str(order) << "\n";

    Infty = my_EC_POINT_new(group);
    assert_s(EC_POINT_set_to_infinity(group, Infty), "could not create point at infinity");

    cerr << "created infinity \n";

    P = randomPoint();

    ZeroBN = BN_new();
    assert_s(ZeroBN != NULL, "cannot create big num");
    BN_zero(ZeroBN);

}

static EC_POINT *
mul(EC_GROUP * group, BIGNUM * ZeroBN, EC_POINT * Point, BIGNUM * Scalar) {

    EC_POINT * ans = EC_POINT_new(group);
    assert_s(ans, "cannot create point ");

    //ans = sk->kp * cbn
    assert_s(EC_POINT_mul(group, ans, ZeroBN, Point, Scalar, NULL), "issue when multiplying ec");

    return ans;
}


ECJoinSK *
ECJoin::getSKey(const string & key) {
    ECJoinSK * skey = new ECJoinSK();
    skey->aesKey = get_AES_KEY(key);

    skey->k = BN_bin2bn((unsigned char *) key.data(), (int) key.length(), NULL);

    assert_s(skey->k != NULL, "failed to convert key to BIGNUM");

    skey->kP = mul(group, ZeroBN, P, skey->k);

    return skey;
}

ECDeltaSK *
ECJoin::getDeltaKey(const ECJoinSK * key1, const ECJoinSK *  key2) {
    ECDeltaSK * delta = new ECDeltaSK();

    delta->group = group;

    BIGNUM * key1Inverse = BN_mod_inverse(NULL, key1->k, order, NULL);
    assert_s(key1Inverse, "could not compute inverse of key 1");

    delta->deltaK = BN_new();
    BN_mod_mul(delta->deltaK, key1Inverse, key2->k, order, NULL);
    assert_s(delta->deltaK, "failed to multiply");

    delta->ZeroBN = ZeroBN;

    BN_free(key1Inverse);

    return delta;

}

// a PRF with 128 bits security, but 160 bit output
string
ECJoin::PRFForEC(const AES_KEY * sk, const string & ptext) {

    string nptext = ptext;

    unsigned int len = (uint) ptext.length();

    if (bytesLong > len) {
        for (unsigned int i = 0 ; i < bytesLong - len; i++) {
            nptext = nptext + "0";
        }
    }

    return encrypt_AES(nptext, sk, 1).substr(0, bytesLong);

}

string
ECJoin::point2Str(EC_GROUP * group, EC_POINT * point) {
    unsigned char buf[ECJoin::MAX_BUF];
    memset(buf, 0, ECJoin::MAX_BUF);

    size_t len = 0;

    len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, buf, len, NULL);

    assert_s(len, "cannot serialize EC_POINT ");

    return string((char *)buf, len);
}

string
ECJoin::encrypt(ECJoinSK * sk, const string & ptext) {

    // CONVERT ptext in PRF(ptext)
    string ctext = PRFForEC(sk->aesKey, ptext);

    //cbn = PRF(ptext)
    BIGNUM * cbn = BN_bin2bn((const unsigned char *) ctext.data(),
                             (uint) ctext.length(), NULL);
    assert_s(cbn, "issue convering string to BIGNUM ");

    //ans = sk->kp * cbn
    EC_POINT * ans = mul(group, ZeroBN, sk->kP, cbn);

    string res = point2Str(group, ans);

    EC_POINT_free(ans);
    BN_free(cbn);

    return res;
}

string
ECJoin::adjust(ECDeltaSK * delta, const string & ctext) {

    EC_POINT * point = EC_POINT_new(delta->group);

    assert_s(EC_POINT_oct2point(delta->group, point, (const unsigned char *)ctext.data(), ctext.length(), NULL),
            "cannot convert from ciphertext to point");

    EC_POINT * res = mul(delta->group, delta->ZeroBN, point, delta->deltaK);

    string result = point2Str(delta->group, res);

    EC_POINT_free(res);
    EC_POINT_free(point);

    return result;
}

ECJoin::~ECJoin()
{
    BN_free(order);
    EC_POINT_free(P);
    EC_GROUP_clear_free(group);
}
