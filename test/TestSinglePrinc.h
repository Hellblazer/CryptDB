/*
 * TestSinglePrinc.h
 *
 *  Created on: Jul 5, 2011
 *      Author: raluca
 */

#include <edb/EDBProxy.h>
#include <test/test_utils.h>

#ifndef TESTSINGLEPRINC_H_
#define TESTSINGLEPRINC_H_

class TestSinglePrinc {
 public:
    TestSinglePrinc();
    virtual
    ~TestSinglePrinc();

    static void run(const TestConfig &tc, int argc, char ** argv);
};

#endif /* TESTSINGLEPRINC_H_ */
