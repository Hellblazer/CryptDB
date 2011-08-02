/*
 * TestCrypto.h
 *
 *  Created on: Jul 15, 2011
 *      Author: cat_red
 */

#pragma once
#include "CryptoManager.h"
#include "HGD.h"
#include "OPE.h"
#include "test_utils.h"

class TestCrypto {
 public:
    TestCrypto();
    virtual
    ~TestCrypto();

    static void run(const TestConfig &tc, int argc, char ** argv);
};
