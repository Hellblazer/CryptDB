/*
 * TestProxy.h
 *
 * Created on: August 3, 2011
 *    Author: cat_red
 */

#include <signal.h>

#include <edb/Connect.hh>
#include <test/test_utils.hh>


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
