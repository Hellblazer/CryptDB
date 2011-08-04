/*
 * TestProxy
 * -- using Connect to check that the proxy works as intended
 *
 *
 */

#include "TestProxy.h"
#include "cryptdb_log.h"

static int ntest = 0;
static int npass = 0;

TestProxy::TestProxy()
{

}

TestProxy::~TestProxy()
{

}

static void
checkQuery(const TestConfig &tc, Connect * conn, const string &query,
	   const vector<string> &names, const vector<vector<string>> &rows) {
    ntest++;
    ResType expected;
    expected.names = names;
    expected.rows = rows;

    DBResult * dbres;
    if (!conn->execute(query, dbres)) {
	LOG(test) << "Query:" << query << " could not execute";
	if (tc.stop_if_fail) {
	    assert_s(false, query + " could not execute");
	}
	return;
    }
    ResType res = dbres->unpack();
    //PrintRes(res);
    if (!match(res, expected)) {
	if (tc.stop_if_fail) {
	    LOG(test) << query << "\nshould have returned:\n";
	    PrintRes(expected);
	    LOG(test) << "but actually returned\n";
	    PrintRes(res);
	    assert_s(false,query + " returned incorrect result");
	}
	return;
    }
    npass++;
}

static void
record(const TestConfig &tc, bool result, string test) {
    ntest++;
    if (!result) {
	if (tc.stop_if_fail) {
	    assert_s(false, test);
	}
	return;
    }
    npass++;
}

static void
CreatePlain(Connect * conn) {
    assert_s(conn->execute("CREATE TABLE t1 (id integer primary key auto_increment, name text, age int, pass text)"), "Couldn't create t1 (plain)");
    assert_s(conn->execute("CREATE TABLE t2 (id integer, so integer, book text)"), "Couldn't create t2 (plain)");
}

static void
CreateSingle(Connect * conn) {
    assert_s(conn->execute("CREATE TABLE t1 (id enc integer primary key auto_increment, name text, age int, pass enc text)"), "Couldn't create t1 (single)");
    assert_s(conn->execute("CREATE TABLE t2 (id enc integer, so enc integer, book enc text)"), "Couldn't create t2 (single)");
}

static void
CreateMulti(Connect * conn) {
    assert_s(conn->execute("CREATE TABLE t1 (id hasaccessto name integer primary key auto_increment, name text, age encfor id int, pass givespsswd id text)"), "Couldn't create t1 (multi)");
    assert_s(conn->execute("CREATE TABLE t2 (id equals t1.id hasaccessto book integer, so equals t1.id hasaccessto t2.book integer, book text)"), "Couldn't create t2 (multi)");
    assert_s(conn->execute("COMMIT ANNOTATIONS"), "Couldn't commit annotations (multi)");
}

static void
Basic(const TestConfig &tc, Connect *conn) {
    string test = "(basic) ";

    //populate tables
    record(tc, conn->execute("INSERT INTO t1 VALUES (1, 'Lymond', 29, 'secretLymond')"), test+"insert Lymond failed");
    record(tc, conn->execute("INSERT INTO t1 VALUES (2, 'Philippa', 20, 'secretPippa')"), test+"insert Philippa failed");
    record(tc, conn->execute("INSERT INTO t1 VALUES (3, 'Oonagh O-Dwyer', 30, 'secretOonagh')"), test+"insert Oonagh failed");
    record(tc, conn->execute("INSERT INTO t1 VALUES (4, 'Phelim O-Liam Roe', 28, 'secretPhelim')"), test+"insert Phelim failed");

    record(tc, conn->execute("INSERT INTO t2 VALUES (1, 3, 'Queens Play')"), test+"insert 1-3 failed");
    record(tc, conn->execute("INSERT INTO t2 VALUES (3, 4, 'Queens Play')"), test+"insert 3-4 failed");
    record(tc, conn->execute("INSERT INTO t2 VALUES (1, 2, 'Checkmate')"), test+"insert 1-2 failed");

    //check inserts worked correctly
    checkQuery(tc, conn, "SELECT * FROM t1",
	       {"id", "name", "age", "pass"},
	       { {"1", "Lymond", "29", "secretLymond"},
		 {"2", "Philippa", "20", "secretPippa"},
		 {"3", "Oonagh O-Dwyer", "30", "secretOonagh"},
		 {"4", "Phelim O-Liam Roe", "28", "secretPhelim"} });
    checkQuery(tc, conn, "SELECT * FROM t2",
	       {"id", "so", "book"},
	       { {"1", "3", "Queens Play"},
		 {"3", "4", "Queens Play"},
		 {"1", "2", "Checkmate"} });

    
}

void
TestProxy::run(const TestConfig &tc, int argc, char ** argv)
{
    
    if (argc > 2 || ((argc == 2) && (strncmp(argv[1], "help", 4) == 0))) {
	cerr << "Command should be    $EDBDIR/tests/test proxy [ single | multi | plain ]\nDefault is to test plain" << endl;
	return;
    }

    pid_t pid = fork();
    if (pid == 0) {
	cerr << "child happened" << endl;
	//run proxy in child
	string edbdir = getenv("EDBDIR");
	string script_path = "--proxy-lua-script=" + edbdir + "/../mysqlproxy/wrapper.lua";
	execl("/usr/local/bin/mysql-proxy", "mysql-proxy", "--plugins=proxy", "--max-open-files=1024", script_path.c_str(), "--proxy-address=localhost:3307", "--proxy-backend-addresses=localhost:3306", (char *) 0);
    } else if (pid < 0) {
	cerr << "failed to fork" << endl;
	exit(1);
    } else {
	sleep(1);
	Connect *conn;
	conn = new Connect(tc.host, tc.user, tc.pass, tc.db, tc.port);
	
	if (argc == 2) {
	    if (strncmp(argv[1], "single", 6) == 0) {
		cerr << "Creating single principle tables" << endl;
		CreateSingle(conn);
	    } else if (strncmp(argv[1], "multi", 5) == 0) {
		cerr << "Creating multi principle tables" << endl;
		CreateMulti(conn);
	    } else if (strncmp(argv[1], "plain", 5) == 0) {
		cerr << "Creating plain principle tables" << endl;
		CreatePlain(conn);
	    }
	} else if (argc == 1) {
	    cerr << "Creating plain principle tables" << endl;
	    CreatePlain(conn);
	}
	
	cerr << "Test simple queries..." << endl;
	Basic(tc, conn);
	//cerr << "Test simple queries (multi principle)..." << endl;
	//BasicMulti();
    
	conn->execute("DROP TABLE t1, t2");
	conn->~Connect();

	cerr << "RESULT: " << npass << "/" << ntest << " passed." << endl;

	//kill child proxy
	kill(pid, SIGKILL);
    }
}
