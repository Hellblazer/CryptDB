/*
 * TestCrypto.h
 *
 *  Created on: Jul 15, 2011
 *      Author: cat_red
 */

#pragma once
#include <edb/CryptoManager.h>
#include <edb/HGD.h>
#include <edb/OPE.h>
#include <edb/tests/test_utils.h>

class TestCrypto {
 public:
    TestCrypto();
    virtual
    ~TestCrypto();

    static void run(const TestConfig &tc, int argc, char ** argv);
};
