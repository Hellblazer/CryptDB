/*
 * TestProxy.h
 *
 * Created on: August 3, 2011
 *    Author: cat_red
 */

#include "Connect.h"
#include "test_utils.h"
#include <signal.h>

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
