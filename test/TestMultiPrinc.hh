/*
 * TestMultiPrinc.h
 *
 * Created on: July 18, 2011
 *  Author: cat_red
 */

#include <test/test_utils.hh>


#ifndef TESTMULTIPRINC_H_
#define TESTMULTIPRINC_H_

class TestMultiPrinc {
 public:
    TestMultiPrinc();
    virtual
    ~TestMultiPrinc();

    static void run(const TestConfig &tc, int argc, char ** argv);
};

#endif /* TESTMULTIPRINC_H_ */
