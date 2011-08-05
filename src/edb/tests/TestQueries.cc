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
static vector<string> query_list = {
    //migrated from TestSinglePrinc TestInsert
    "INSERT INTO test_insert VALUES (1, 21, 100, '24 Rosedale, Toronto, ONT', 'Pat Carlson')",
    "SELECT * FROM test_insert",
    "INSERT INTO test_insert (id, age, salary, address, name) VALUES (2, 23, 101, '25 Rosedale, Toronto, ONT', 'Pat Carlson2')",
    "SELECT * FROM test_insert",
    "INSERT INTO test_insert (age, address, salary, name, id) VALUES (25, '26 Rosedale, Toronto, ONT', 102, 'Pat2 Carlson', 3)",
    "SELECT * FROM test_insert",
    "INSERT INTO test_insert (age, address, salary, name) VALUES (26, 'test address', 30, 'test name')",
    "SELECT * FROM test_insert",
    "INSERT INTO test_insert (age, address, salary, name) VALUES (27, 'test address2', 31, 'test name')",
    "select last_insert_id()",
    "INSERT INTO test_insert (id) VALUES (7)",
    "select sum(id) from test_insert",
    "INSERT INTO test_insert (age) VALUES (40)",
    "SELECT age FROM test_insert",
    "INSERT INTO test_insert (name) VALUES ('Wendy')",
    "SELECT name FROM test_insert WHERE id=10",
    "INSERT INTO test_insert (name, address, id, age) VALUES ('Peter Pan', 'first star to the right and straight on till morning', 42, 10)",
    "SELECT name, address, age FROM test_insert WHERE id=42",
    "DROP TABLE test_insert",
    //migrated from TestSinglePrinc TestSelect
    "INSERT INTO test_select VALUES (1, 10, 0, 'first star to the right and straight on till morning', 'Peter Pan')",
    "INSERT INTO test_select VALUES (2, 16, 1000, 'Green Gables', 'Anne Shirley')",
    "INSERT INTO test_select VALUES (3, 8, 0, 'London', 'Lucy')",
    "INSERT INTO test_select VALUES (4, 10, 0, 'London', 'Edmund')",
    "INSERT INTO test_select VALUES (5, 30, 100000, '221B Baker Street', 'Sherlock Holmes')",
    "SELECT * FROM test_select",
    "SELECT max(id) FROM test_select",
    "SELECT max(salary) FROM test_select",
    "SELECT COUNT(*) FROM test_select",
    "SELECT COUNT(DISTINCT age) FROM test_select",
    "SELECT COUNT(DISTINCT(address)) FROM test_select",
    "SELECT name FROM test_select",
    "SELECT address FROM test_select",
    "SELECT * FROM test_select WHERE id>3",
    "SELECT * FROM test_select WHERE age = 8",
    "SELECT * FROM test_select WHERE salary=15",
    "SELECT * FROM test_select WHERE age > 10",
    "SELECT * FROM test_select WHERE age = 10 AND salary = 0",
    "SELECT * FROM test_select WHERE age = 10 OR salary = 0",
    "SELECT * FROM test_select WHERE name = 'Peter Pan'",
    "SELECT * FROM test_select WHERE address='Green Gables'",
    "SELECT * FROM test_select WHERE address <= '221C'",
    "SELECT * FROM test_select WHERE address >= 'Green Gables' AND age > 9",
    "SELECT * FROM test_select WHERE address >= 'Green Gables' OR age > 9",
    "SELECT * FROM test_select ORDER BY id",
    "SELECT * FROM test_select ORDER BY salary",
    "SELECT * FROM test_select ORDER BY name",
    "SELECT * FROM test_select ORDER BY address",
    "SELECT sum(age) FROM test_select GROUP BY address",
    "SELECT salary, max(id) FROM test_select GROUP BY salary",
    "SELECT * FROM test_select GROUP BY age ORDER BY age",
    "SELECT * FROM test_select ORDER BY age ASC",
    "SELECT * FROM test_select ORDER BY address DESC",
    "SELECT sum(age) as z FROM test_select",
    "SELECT sum(age) z FROM test_select",
    "SELECT min(t.id) a FROM test_select AS t",
    "SELECT t.address AS b FROM test_select t",
    "DROP TABLE test_select",
    //migrated from TestSinglePrinc TestJoin
    "INSERT INTO test_join1 VALUES (1, 10, 0, 'first star to the right and straight on till morning','Peter Pan')",
    "INSERT INTO test_join1 VALUES (2, 16, 1000, 'Green Gables', 'Anne Shirley')",
    "INSERT INTO test_join1 VALUES (3, 8, 0, 'London', 'Lucy')",
    "INSERT INTO test_join1 VALUES (4, 10, 0, 'London', 'Edmund')",
    "INSERT INTO test_join1 VALUES (5, 30, 100000, '221B Baker Street', 'Sherlock Holmes')",
    "INSERT INTO test_join2 VALUES (1, 6, 'Peter Pan')",
    "INSERT INTO test_join2 VALUES (2, 8, 'Anne Shirley')",
    "INSERT INTO test_join2 VALUES (3, 7, 'Lucy')",
    "INSERT INTO test_join2 VALUES (4, 7, 'Edmund')",
    "INSERT INTO test_join2 VALUES (10, 4, '221B Baker Street')",
    "SELECT address FROM test_join1, test_join2 WHERE test_join1.id=test_join2.id",
    "SELECT test_join1.id, test_join2.id, age, books, test_join2.name FROM test_join1, test_join2 WHERE test_join1.id = test_join2.id",
    "SELECT test_join1.name, age, salary, test_join2.name, books FROM test_join1, test_join2 WHERE test_join1.age=test_join2.books",
    "SELECT * FROM test_join1, test_join2 WHERE test_join1.name=test_join2.name",
    "SELECT * FROM test_join1, test_join2 WHERE test_join1.address=test_join2.name",
    "SELECT address FROM test_join1 AS a, test_join2 WHERE a.id=test_join2.id",
    "SELECT a.id, b.id, age, books, b.name FROM test_join1 a, test_join2 AS b WHERE a.id=b.id",
    "SELECT test_join1.name, age, salary, b.name, books FROM test_join1, test_join2 b WHERE test_join1.age = b.books",
    "DROP TABLE test_join1",
    "DROP TABLE test_join2",
    //migrated from TestSinglePrinc TestUpdate
    "INSERT INTO test_update VALUES (1, 10, 0, 'first star to the right and straight on till morning','Peter Pan')",
    "INSERT INTO test_update VALUES (2, 16, 1000, 'Green Gables', 'Anne Shirley')",
    "INSERT INTO test_update VALUES (3, 8, 0, 'London', 'Lucy')",
    "INSERT INTO test_update VALUES (4, 10, 0, 'London', 'Edmund')",
    "INSERT INTO test_update VALUES (5, 30, 100000, '221B Baker Street', 'Sherlock Holmes')",
    "INSERT INTO test_update VALUES (6, 11, 0 , 'hi', 'no one')",
    "UPDATE test_update SET salary=0",
    "SELECT * FROM test_update",
    "UPDATE test_update SET age=21 WHERE id = 6",
    "SELECT * FROM test_update",
    "UPDATE test_update SET address='Pemberly', name='Elizabeth Darcy' WHERE id=6",
    "SELECT * FROM test_update",
    "UPDATE test_update SET salary=55000 WHERE age=30",
    "SELECT * FROM test_update",
    "UPDATE test_update SET salary=20000 WHERE address='Pemberly'",
    "SELECT * FROM test_update",
    "SELECT age FROM test_update WHERE age > 20",
    "SELECT id FROM test_update",
    "SELECT sum(age) FROM test_update",
    "UPDATE test_update SET age=20 WHERE name='Elizabeth Darcy'",
    "SELECT * FROM test_update WHERE age > 20",
    "SELECT sum(age) FROM test_update",
    "UPDATE test_update SET age = age + 2",
    "SELECT age FROM test_update",
    "UPDATE test_update SET id = id + 10, salary = salary + 19, name = 'xxx', address = 'foo' WHERE address = 'London'",
    "SELECT * FROM test_update",
    "SELECT * FROM test_update WHERE address < 'fml'",
    "UPDATE test_update SET address = 'Neverland' WHERE id=1",
    "SELECT * FROM test_update",
    "DROP TABLE test_update",
    //migrated from TestDelete
    "INSERT INTO test_delete VALUES (1, 10, 0, 'first star to the right and straight on till morning','Peter Pan')",
    "INSERT INTO test_delete VALUES (2, 16, 1000, 'Green Gables', 'Anne Shirley')",
    "INSERT INTO test_delete VALUES (3, 8, 0, 'London', 'Lucy')",
    "INSERT INTO test_delete VALUES (4, 10, 0, 'London', 'Edmund')",
    "INSERT INTO test_delete VALUES (5, 30, 100000, '221B Baker Street', 'Sherlock Holmes')",
    "INSERT INTO test_delete VALUES (6, 21, 2000, 'Pemberly', 'Elizabeth')",
    "INSERT INTO test_delete VALUES (7, 10000, 1, 'Mordor', 'Sauron')",
    "INSERT INTO test_delete VALUES (8, 25, 100, 'The Heath', 'Eustacia Vye')",
    "DELETE FROM test_delete WHERE id=1",
    "SELECT * FROM test_delete",
    "DELETE FROM test_delete WHERE age=30",
    "SELECT * FROM test_delete",
    "DELETE FROM test_delete WHERE name='Eustacia Vye'",
    "SELECT * FROM test_delete",
    "DELETE FROM test_delete WHERE address='London'",
    "SELECT * FROM test_delete",
    "DELETE FROM test_delete WHERE salary = 1",
    "SELECT * FROM test_delete",
    "INSERT INTO test_delete VALUES (1, 10, 0, 'first star to the right and straight on till morning','Peter Pan')",
    "SELECT * FROM test_delete",
    "DELETE FROM test_delete",
    "SELECT * FROM test_delete",
    "DROP TABLE test_delete",
    //migrated from TestSearch
    "INSERT INTO test_search VALUES (1, 'short text')",
    "INSERT INTO test_search VALUES (2, 'Text with CAPITALIZATION')",
    "INSERT INTO test_search VALUES (3, '')",
    "INSERT INTO test_search VALUES (4, 'When I have fears that I may cease to be, before my pen has gleaned my teeming brain; before high piled books in charactery hold like ruch garners the full-ripened grain. When I behold on the nights starred face huge cloudy symbols of high romance and think that I may never live to trace their shadows with the magic hand of chance; when I feel fair creature of the hour that I shall never look upon thee more, never have relish of the faerie power of unreflecting love, I stand alone on the edge of the wide world and think till love and fame to nothingness do sink')",
    "SELECT * FROM test_search WHERE searchable LIKE '%text%'",
    "SELECT * FROM test_search WHERE searchable LIKE 'short%'",
    "SELECT * FROM test_search WHERE searchable LIKE ''",
    "SELECT * FROM test_search WHERE searchable LIKE '%capitalization'",
    "SELECT * FROM test_search WHERE searchable LIKE 'noword'",
    "SELECT * FROM test_search WHERE searchable LIKE 'when%'",
    "SELECT * FROM test_search WHERE searchable < 'slow'",
    "UPDATE test_search SET searchable='text that is new' WHERE id=1",
    "SELECT * FROM test_search WHERE searchable < 'slow'",
    "DROP TABLE test_search",
};
static vector<string> plain_create = {
    "CREATE TABLE test_insert (id integer primary key auto_increment, age integer, salary integer, address text, name text)",
    "CREATE TABLE test_select (id integer, age integer, salary integer, address text, name text)",
    "CREATE TABLE test_join1 (id integer, age integer, salary integer, address text, name text)",
    "CREATE TABLE test_join2 (id integer, books integer, name text)",
    "CREATE TABLE test_update (id integer, age integer, salary integer, address text, name text)",
    "CREATE TABLE test_delete (id integer, age integer, salary integer, address text, name text)",
    "CREATE TABLE test_search (id integer, searchable text)"
};
static vector<string> single_create = {
    "CREATE TABLE test_insert (id integer primary key auto_increment, age enc integer, salary enc integer, address enc text, name text)",
    "CREATE TABLE test_select (id integer, age enc integer, salary enc integer, address enc text, name text)",
    "CREATE TABLE test_join1 (id integer, age enc integer, salary enc integer, address enc text, name text)",
    "CREATE TABLE test_join2 (id integer, books enc integer, name enc text)",
    "CREATE TABLE test_update (id integer, age enc integer, salary enc integer, address enc text, name enc text)",
    "CREATE TABLE test_delete (id integer, age enc integer, salary enc integer, address enc text, name enc text)",
    "CREATE TABLE test_search (id integer, searchable enc search text)"
};
static vector<string> multi_create = {
    "CREATE TABLE test_insert (id integer primary key auto_increment, age integer, salary integer, address text, name text)",
    "CREATE TABLE test_select (id integer, age integer, salary integer, address text, name text)",
    "CREATE TABLE test_join1 (id integer, age integer, salary integer, address text, name text)",
    "CREATE TABLE test_join2 (id integer, books integer, name text)",
    "CREATE TABLE test_update (id integer, age integer, salary integer, address text, name text)",
    "CREATE TABLE test_delete (id integer, age enc integer, salary enc integer, address enc text, name enc text)",
    "CREATE TABLE test_search (id integer, searchable enc search text)"
};

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
    cerr << query << endl;
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

    for (unsigned int i = 0; i < plain_create.size(); i++) {
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

    //query: do they need their own tc? yes!  different dbs
    TestConfig control_tc = TestConfig();
    control_tc.db = control_tc.db+"_control";
    
    control = new Connection(control_tc, control_type);
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

