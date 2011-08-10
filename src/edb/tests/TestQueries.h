/*
 * TestQueries.h
 *
 */

#include "EDBClient.h"
#include "Connect.h"
#include "test_utils.h"
#include <signal.h>
#include <stdlib.h>

#ifndef TESTQUERIES_H_
#define TESTQUERIES_H_

struct Query {
    string query;
    bool multi_null;

    Query()
    {
    }

    Query(string q, bool returns_null_multi) {
        query = q;
        multi_null = returns_null_multi;
    }
};

struct QueryList {
    string name;
    vector<string> plain_create;
    vector<string> single_create;
    vector<string> multi_create;
    vector<Query> common;
    vector<string> plain_drop;
    vector<string> single_drop;
    vector<string> multi_drop;

    QueryList() 
    {
    }

    QueryList(string namearg, vector<string> pc, vector<string> sc, vector<string> mc, vector<Query> c, vector<string> pd, vector<string> sd, vector<string> md) {
        name = namearg;
        plain_create = pc;
        single_create = sc;
        multi_create = mc;
        common = c;
        plain_drop = pd;
        single_drop = sd;
        multi_drop = md;
    }
};

typedef enum test_mode {UNENCRYPTED, SINGLE, MULTI, PROXYPLAIN, PROXYSINGLE, PROXYMULTI} test_mode;

class Connection {
 public:
    Connection(const TestConfig &tc, test_mode type);
    ~Connection();

    ResType execute(string query);

    void restart();
    void start();
    void stop();

 private:
    test_mode type;
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
    ~TestQueries();

    static void run(const TestConfig &tc, int argc, char ** argv);

};

#endif /* TESTQUERIES_H_ */
