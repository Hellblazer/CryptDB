/*
 * TestQueries.cc
 *  -- end to end query and result test, independant of connection process
 *
 *
 */

#include "TestQueries.h"
#include "cryptdb_log.h"

static int ntest = 0;
static int npass = 0;
static int control_type;
static int test_type;
static int no_conn = 1;
static Connection * control;
static Connection * test;
static vector<string> query_list;
static vector<string> plain_create;
static vector<string> single_create;
static vector<string> multi_create;

Connection::Connection(const TestConfig &input_tc, int input_type) {
    if (input_type > 3) { 
        this->type = 3;
    } else {
        this->type = input_type;
    }
    this->tc = input_tc;

    uint64_t mkey = 1133421234;
    string masterKey = BytesFromInt(mkey, AES_KEY_BYTES); 
    switch (type) {
        //plain -- new connection straight to the DB
    case 0:
        conn = new Connect(tc.host, tc.user, tc.pass, tc.db, 0);
        break;
        //single -- new EDBClient
    case 1:
        cl = new EDBClient(tc.host, tc.user, tc.pass, tc.db, 0, false);
        cl->setMasterKey(masterKey);
        break;
        //multi -- new EDBClient
    case 2:
        cl = new EDBClient(tc.host, tc.user, tc.pass, tc.db, 0, true);
        cl->setMasterKey(masterKey);
        break;
        //proxy -- start proxy in separate process and initialize connection
    case 3:
        proxy_pid = fork();
        if (proxy_pid == 0) {
            string edbdir = getenv("EDBDIR");
            string script_path = "--proxy-lua-script="+edbdir+"/../mysqlproxy/wrapper.lua";
            execl("/usr/local/bin/mysql-proxy", "mysql-proxy", "--plugins=proxy", "--max-open-files=1024", script_path.c_str(), "--proxy-address=localhost:3307", "--proxy-backend-addresses=localhost:3306", (char *) 0);
        } else if (proxy_pid < 0) {
            cerr << "failed to fork" << endl;
            exit(1);
        } else {
            sleep(1);
            conn = new Connect(tc.host, tc.user, tc.pass, tc.db, tc.port);
        }
        break;
    default:
        assert_s(false, "invalid type passed to Connection");
    }
}

Connection::~Connection() {
    switch (type) {
    case 0:
        delete conn;
        break;
    case 1:
    case 2:
        delete cl;
        break;
    case 3:
        kill(proxy_pid, SIGKILL);
        delete conn;
        break;
    default:
        break;
    }
}

ResType
Connection::execute(string query) {
    switch (type) {
    case 0:
    case 3:
        return executeConn(query);
    case 1:
    case 2:
        return executeEDBClient(query);
    default:
        assert_s(false, "unrecognized type in Connection");
    }
    return ResType(false);
}

void
Connection::executeFail(string query) {
    LOG(test) << "Query: " << query << " could not execute" << endl;
    if(tc.stop_if_fail) {
        assert_s(false, query + " could not execute");
    }
}

ResType
Connection::executeEDBClient(string query) {
    ResType res = cl->execute(query);
    if (!res.ok) {
        executeFail(query);
    }
    return res;
}
    
ResType
Connection::executeConn(string query) {
    DBResult * dbres;
    if (!conn->execute(query, dbres)) {
        executeFail(query);
        return ResType(false);
    }
    return dbres->unpack();
}
 
//----------------------------------------------------------------------

static void
CheckCreateQuery(const TestConfig &tc, string control_query, string test_query) {
    ntest++;

    ResType control_res = control->execute(control_query);
    ResType test_res = test->execute(test_query);
    if (!match(test_res, control_res)) {
        //TODO: figure out how to LOG resultsets
        LOG(test) << "On query: " << test_query << "\nwe received the incorrect resultset";
        if (tc.stop_if_fail) {
            PrintRes(control_res);
            PrintRes(test_res);
            assert_s(false, test_query+" returned second resultset, should have returned first");
        }
        return;
    }
    
    npass++;
}

static void
CheckQuery(const TestConfig &tc, string query) {
    CheckCreateQuery(tc, query, query);
}

static void
RunTest(const TestConfig &tc) {
    assert_s(plain_create.size() == single_create.size() && plain_create.size() == multi_create.size(), "create query lists are not the same size");

    for (unsigned int i = 0; i <= plain_create.size(); i++) {
        string control_query;
        string test_query;
        switch(control_type) {
        case 0:
        case 3:
            control_query = plain_create[i];
            break;
        case 1:
        case 4:
            control_query = single_create[i];
            break;
        case 2:
        case 5:
            control_query = multi_create[i];
            break;
        default:
            assert_s(false, "control_type invalid");
        }
        switch(test_type) {
        case 0:
        case 3:
            test_query = plain_create[i];
            break;
        case 1:
        case 4:
            test_query = single_create[i];
            break;
        case 2:
        case 5:
            test_query = multi_create[i];
            break;
        default:
            assert_s(false, "test_type invalid");
        }
        CheckCreateQuery(tc, control_query, test_query);
    }

    for (auto query = query_list.begin(); query != query_list.end(); query++) {
        CheckQuery(tc, *query);
    }

    //TODO: add stuff for multiple connections
}


//---------------------------------------------------------------------

TestQueries::TestQueries() {
}

TestQueries::~TestQueries() {
}

void
TestQueries::run(const TestConfig &tc, int argc, char ** argv) {
    switch(argc) {
    case 4:
        //TODO: set no_conn from argv[3]
        cerr << "currently we only support one connection" << endl;
        no_conn = 1;
    case 3:
        if (strncmp(argv[1],"plain",5) == 0) {
            control_type = 0;
        } else if (strncmp(argv[1], "single", 6) == 0) {
            control_type = 1;
        } else if (strncmp(argv[1], "multi", 5) == 0) {
            control_type = 2;
        } else if (strncmp(argv[1], "proxy-plain", 11) == 0) {
            control_type = 3;
        } else if (strncmp(argv[1], "proxy-single", 12) == 0) {
            control_type = 4;
            //TODO: check proxy is setting up in single mode... not quite sure how to do this...
        } else if (strncmp(argv[1], "proxy-multi", 11) == 0) {
            control_type = 5;
            //TODO: check proxy is setting up in multi mode... not quite sure how to do this...
        } else {
            cerr << "control is not recognized" << endl;
            return;
        }

        if (strncmp(argv[2],"plain",5) == 0) {
            test_type = 0;
        } else if (strncmp(argv[2], "single", 6) == 0) {
            test_type = 1;
        } else if (strncmp(argv[2], "multi", 5) == 0) {
            test_type = 2;
        } else if (strncmp(argv[2], "proxy-plain", 11) == 0) {
            test_type = 3;
        } else if (strncmp(argv[2], "proxy-single", 12) == 0) {
            test_type = 4;
            //TODO: check proxy is setting up in single mode... not quite sure how to do this...
        } else if (strncmp(argv[2], "proxy-multi", 11) == 0) {
            test_type = 5;
            //TODO: check proxy is setting up in multi mode... not quite sure how to do this...
        } else {
            cerr << "test is not recognized" << endl;
            return;
        }
        
        break;
    default:
        cerr << "Wrong number of arguments.  Take arguments:\n\ttests/test queries control test [number_connections]\n  control and test are [ plain | single | multi | proxy-plain | proxy-single | proxy-multi ] which refers to the type of connections being made; control's results are assumed to be correct, so it is suggested that plain is used for control\n  test is the connection that is being tested; it's results are checked against control's\n   (single and multi make connections through EDBClient; proxy-* makes connections *'s encryption type through the proxy)\n  number_connections is the number of connections test are making a single database, with default of 1" << endl;
        return;
    }        

    //query: do they need their own tc?
    
    control = new Connection(tc, control_type);
    test = new Connection(tc, test_type);

    RunTest(tc);

    delete control;
    delete test;
    query_list.clear();
    plain_create.clear();
    single_create.clear();
    multi_create.clear();

    cerr << "RESULT: " << npass << "/" << ntest << endl;
}

