/*
 * TestCrypto.h
 *
 *  Created on: Jul 15, 2011
 *      Author: cat_red
 */

#pragma once
#include <crypto-old/CryptoManager.h>
#include <crypto-old/HGD.h>
#include <crypto-old/OPE.h>
#include <test/test_utils.h>

class TestCrypto {
 public:
    TestCrypto();
    virtual
    ~TestCrypto();

    static void run(const TestConfig &tc, int argc, char ** argv);
};
