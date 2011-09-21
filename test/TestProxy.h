/*
 * TestProxy.h
 *
 * Created on: August 3, 2011
 *    Author: cat_red
 */

#include <signal.h>
#include <edb/Connect.h>
#include <edb/tests/test_utils.h>

#ifndef TESTPROXY_H_
#define TESTPROXY_H_

class TestProxy {
 public:
    TestProxy();
    virtual
    ~TestProxy();
    
    static void run(const TestConfig &tc, int argc, char ** argv);
};

#endif /*TESTPROXY_H_ */
