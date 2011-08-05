/*
 * TestQueries.h
 *
 */

#include "EDBClient.h"
#include "Connect.h"
#include "test_utils.h"
#include <signal.h>

#ifndef TESTQUERIES_H_
#define TESTQUERIES_H_

class Connection {
 public:
    Connection(const TestConfig &tc, int type);
    virtual
        ~Connection();

    ResType execute(string query);

 private:
    int type;
    TestConfig tc;
    //connection objects for encryption test
    EDBClient * cl;
    //connection objects for plain and proxy test
    Connect * conn;
    pid_t proxy_pid;

    ResType executeConn(string query);
    ResType executeEDBClient(string query);

    void executeFail(string query);
};

class TestQueries {
 public:
    TestQueries();
    virtual
        ~TestQueries();

    static void run(const TestConfig &tc, int argc, char ** argv);

};

#endif /* TESTQUERIES_H_ */
