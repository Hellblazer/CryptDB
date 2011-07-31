/*
 * TestMultiPrinc
 * -- tests multi principal end-to-end within cryptdb (no proxy tests)
 *
 *
 */

#include "TestMultiPrinc.h"
#include "cryptdb_log.h"

static int ntest = 0;
static int npass = 0;

TestMultiPrinc::TestMultiPrinc()
{

}

TestMultiPrinc::~TestMultiPrinc()
{

}

static void
checkQuery(const TestConfig &tc, EDBClient * cl, const string &query,
           const vector<string> &names, const vector<vector<string>> &rows)
{
    ResType expect;
    expect.names = names;
    expect.rows = rows;

    ntest++;
    ResType test_res = myExecute(cl, query);
    if (!test_res.ok) {
        LOG(test) << "Query: " << query << " cannot execute";
        if (tc.stop_if_fail) {
            assert_s(false, "above query could not execute");
        }
        return;
    }

    if (!match(test_res, expect)) {
        LOG(test) << "On query:\n" << query;
        LOG(test) << "we expected resultset:";
        PrintRes(expect);
        LOG(test) << "but it returned:";
        PrintRes(test_res);
        if (tc.stop_if_fail) {
            assert_s(false, "above query returned incorrect result");
        }
        return;
    }

    npass++;
}

static void
testNULL(const TestConfig &tc, EDBClient * cl, const string &annotated, const string &plain) {
  ntest++;
  if (myCreate(cl, annotated, plain).ok) {
    if (PLAIN) {
      LOG(test) << "Query:\n" << plain;
    } else {
      LOG(test) << "Query:\n" << annotated;
    }
    LOG(test) << "did not return NULL";
    if (tc.stop_if_fail) {
      assert_s(false, "above query did not fail (should have)");
    }
    return;
  }
  npass++;
}

static void
BasicFunctionality(const TestConfig &tc, EDBClient * cl)
{
    cl->plain_execute(
        "DROP TABLE IF EXISTS u, t1, plain_users, pwdcryptdb__users, cryptdb_publis, cryptdb_initialized_principals, cryptdb0;");
    assert_res(myCreate(
                 cl,
                 "CREATE TABLE t1 (id integer, post encfor id det text, age encfor id ope bigint);",
                 "CREATE TABLE t1 (id integer, post text, age bigint);"),
             "failed (1)");
    assert_res(myCreate(
                 cl,
                 "CREATE TABLE u (id equals t1.id integer, username givespsswd id text);",
                 "CREATE TABLE u (id integer, username text);"),
             "failed (2)");
    assert_res(myCreate(cl,"COMMIT ANNOTATIONS;",
                      "CREATE TABLE plain_users (username text, psswd text)"),
             "problem commiting annotations");

    //check insert into users (doesn't effect actual db)
    myCreate(
        cl,"INSERT INTO "+ PWD_TABLE_PREFIX +
        "users (username, psswd) VALUES ('alice','secretalice');",
        "INSERT INTO plain_users (username, psswd) VALUES ('alice','secretalice');");

    myCreate(
        cl,"DELETE FROM "+ PWD_TABLE_PREFIX +
        "users WHERE username = 'alice';",
        "DELETE FROM plain_users WHERE username = 'alice';");

    myCreate(
        cl,"INSERT INTO "+ PWD_TABLE_PREFIX +
        "users (username, psswd) VALUES ('alice','secretalice');",
        "INSERT INTO plain_users (username, psswd) VALUES ('alice','secretalice');");

    //check responses to normal queries
    checkQuery(tc, cl,"INSERT INTO u VALUES (1, 'alice')", {}, {});

    checkQuery(tc, cl, "SELECT * FROM u",
               {"id", "username"},
               { {"1", "alice"} });

    checkQuery(tc, cl,"INSERT INTO t1 VALUES (1, 'text which is inserted', 23)", {}, {});

    checkQuery(tc, cl,"SELECT * FROM t1",
               {"id", "post", "age"},
               { {"1", "text which is inserted", "23"} });

    checkQuery(tc, cl,"SELECT post FROM t1 WHERE id = 1 AND age = 23",
               {"post"},
               { {"text which is inserted"} });

    checkQuery(tc, cl,"UPDATE t1 SET post = 'hello!' WHERE age > 22 AND id = 1",
               {}, {});

    checkQuery(tc, cl,"SELECT * FROM t1",
               {"id", "post", "age"},
               { {"1", "hello!", "23"} });

    myCreate(
        cl,"INSERT INTO "+ PWD_TABLE_PREFIX +
        "users (username, psswd) VALUES ('raluca','secretraluca');",
        "INSERT INTO plain_users (username, psswd) VALUES ('raluca','secretraluca');");

    checkQuery(tc, cl,"INSERT INTO u VALUES (2, 'raluca');", {}, {});

    checkQuery(tc, cl,"SELECT * FROM u",
               {"id","username"},
               { {"1", "alice"},
                 {"2", "raluca"} });

    checkQuery(tc, cl,"INSERT INTO t1 VALUES (2, 'raluca has text here', 5)",
               {}, {});

    checkQuery(tc, cl,"SELECT * FROM t1",
               {"id", "post", "age"},
               { {"1","hello!","23"},
                 {"2","raluca has text here","5"} });

}

static void
PrivMessages(const TestConfig &tc, EDBClient * cl)
{
    cl->plain_execute(
        "DROP TABLE IF EXISTS u, msgs, privmsg, plain_users, pwdcryptdb__users, cryptdb_publis, cryptdb_initialized_principals, cryptdb0;");
    assert_res(myCreate(
                 cl,
                 "CREATE TABLE msgs (msgid equals privmsg.msgid integer, msgtext encfor msgid text)",
                 "CREATE TABLE msgs (msgid integer, msgtext text)"),
             "failed: msgs table");
    assert_res(myCreate(
                 cl,
                 "CREATE TABLE privmsg (msgid integer, recid equals u.userid hasaccessto msgid integer, senderid hasaccessto msgid integer)",
                 "CREATE TABLE privmsg (msgid integer, recid integer, senderid integer)"),
             "failed: privmsges table");
    assert_res(myCreate(
                 cl,
                 "CREATE TABLE u (userid equals privmsg.senderid integer, username givespsswd userid text);",
                 "CREATE TABLE u (userid integer, username text);"),
             "failed: u table");
    assert_res(myCreate(cl,"COMMIT ANNOTATIONS;",
                      "CREATE TABLE plain_users (username text, psswd text)"),
             "problem commiting annotations");

    myCreate(
        cl,"INSERT INTO "+ PWD_TABLE_PREFIX +
        "users (username, psswd) VALUES ('alice','secretalice');",
        "INSERT INTO plain_users (username, psswd) VALUES ('alice','secretalice');");
    myCreate(
        cl,"INSERT INTO "+ PWD_TABLE_PREFIX +
        "users (username, psswd) VALUES ('bob','secretbob');",
        "INSERT INTO plain_users (username, psswd) VALUES ('bob','secretbob');");

    checkQuery(tc, cl,"INSERT INTO u VALUES (1, 'alice')",{}, {});
    checkQuery(tc, cl,"INSERT INTO u VALUES (2, 'bob')",{}, {});

    checkQuery(
        tc, cl,"INSERT INTO privmsg (msgid, recid, senderid) VALUES (9, 1, 2)",
        {}, {});
    checkQuery(tc, cl,"INSERT INTO msgs VALUES (1, 'hello world')",{}, {});

    checkQuery(tc, cl,"SELECT msgtext from msgs WHERE msgid = 1",
               {"msgtext"},
               { {"hello world"} });
    checkQuery(
        tc, cl,
        "SELECT msgtext from msgs, privmsg, u WHERE username = 'alice' AND userid = recid AND msgs.msgid = privmsg.msgid",
        {}, {});

    checkQuery(tc, cl,"INSERT INTO msgs VALUES (9, 'message for alice from bob')",
               {}, {});
    checkQuery(
        tc, cl,
        "SELECT msgtext from msgs, privmsg, u WHERE username = 'alice' AND userid = recid AND msgs.msgid = privmsg.msgid",
        {"msgtext"},
        { {"message for alice from bob"} });

    //TODO: extend this test
}

static void
UserGroupForum(const TestConfig &tc, EDBClient * cl) {
    cl->plain_execute("DROP TABLE IF EXISTS u, usergroup, groupforum, forum, plain_users, pwdcryptdb__users, cryptdb_public, cryptdb_initialized_principals, cryptdb0;");
    assert_res(myCreate(cl,"CREATE TABLE u (userid integer, username givespsswd userid text);",
                      "CREATE TABLE u (userid integer, username text);"),
                         "failed: u table");
    assert_res(myCreate(cl,"CREATE TABLE usergroup (userid equals u.userid hasaccessto groupid integer, groupid integer)",
                      "CREATE TABLE usergroup (userid integer, groupid integer)"), "failed: usergroup table");
    assert_res(myCreate(cl,"CREATE TABLE groupforum (forumid equals forum.forumid integer, groupid equals usergroup.groupid hasaccessto forumid integer, optionid integer)",
                      "CREATE TABLE groupforum (forumid integer, groupid integer, optionid integer)"), "failed: groupforum table");
    assert_res(myCreate(cl,"CREATE TABLE forum (forumid integer, forumtext encfor forumid text)",
                      "CREATE TABLE forum (forumid integer, forumtext text)"),
                         "failed: forum table");
    cl->plain_execute("DROP FUNCTION IF EXISTS test");
    cl->plain_execute("CREATE FUNCTION test (optionid integer) RETURNS bool RETURN optionid=20");

    assert_res(myCreate(cl,"COMMIT ANNOTATIONS;","CREATE TABLE plain_users (username text, psswd text)"), "problem commiting annotations");

    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('alice','secretalice');","INSERT INTO plain_users (username, psswd) VALUES ('alice','secretalice');");
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('bob','secretbob');","INSERT INTO plain_users (username, psswd) VALUES ('bob','secretbob');");
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('chris','secretchris');","INSERT INTO plain_users (username, psswd) VALUES ('chris','secretchris');");

    //populate things while everyone is logged in
    checkQuery(tc, cl,"INSERT INTO u VALUES (1, 'alice')",{}, {});
    checkQuery(tc, cl,"INSERT INTO u VALUES (2, 'bob')",{}, {});
    checkQuery(tc, cl,"INSERT INTO u VALUES (3, 'chris')",{}, {});

    checkQuery(tc, cl,"INSERT INTO usergroup VALUES (1,1)",{}, {});
    checkQuery(tc, cl,"INSERT INTO usergroup VALUES (2,2)",{}, {});
    checkQuery(tc, cl,"INSERT INTO usergroup VALUES (3,1)",{}, {});
    checkQuery(tc, cl,"INSERT INTO usergroup VALUES (3,2)",{}, {});

    checkQuery(tc, cl,"SELECT * FROM usergroup",
               {"userid", "groupid"},
               { {"1","1"},
                 {"2","2"},
                 {"3","1"},
                 {"3","2"} });

    checkQuery(tc, cl,"INSERT INTO groupforum VALUES (1,1,14)",{}, {});
    checkQuery(tc, cl,"INSERT INTO groupforum VALUES (1,1,20)",{}, {});

    return;

    checkQuery(tc, cl,"SELECT * FROM groupforum",
           {"forumid","groupid","optionid"},
           { {"1","1","14"},
         {"1","1","20"} } );

    checkQuery(tc, cl,"INSERT INTO forum VALUES (1,'success-- you can see forum text')",{}, {});

    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='alice';",
         "DELETE FROM plain_users WHERE username='alice'");
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='bob';",
         "DELETE FROM plain_users WHERE username='bob'");
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='chris';",
         "DELETE FROM plain_users WHERE username='chris'");

    //alice
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('alice','secretalice');",
         "INSERT INTO plain_users (username, psswd) VALUES ('alice','secretalice');");
    checkQuery(tc, cl,"SELECT forumtext from forum WHERE forumid=1",
           {"forumtext"},
           { {"success-- you can see forum text"} } );
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='alice';",
         "DELETE FROM plain_users WHERE username='alice'");
    
    //bob
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('bob','secretbob');",
         "INSERT INTO plain_users (username, psswd) VALUES ('bob','secretbob');");
    testNULL(tc, cl,"SELECT forumtext from forum WHERE forumid=1","");
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='bob';",
         "DELETE FROM plain_users WHERE username='bob'");    

    //chris
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('chris','secretchris');",
         "INSERT INTO plain_users (username, psswd) VALUES ('chris','secretchris');");
    checkQuery(tc, cl,"SELECT forumtext from forum WHERE forumid=1",
           {"forumtext"},
           { {"success-- you can see forum text"} } );
    checkQuery(tc, cl,"UPDATE forum SET forumtext='you win!' WHERE forumid=1",{}, {});
    checkQuery(tc, cl,"SELECT forumtext from forum WHERE forumid=1",
           {"forumtext"},
           { {"you win!"} } );
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='chris';",
         "DELETE FROM plain_users WHERE username='chris'");    

    //alice
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('alice','secretalice');",
         "INSERT INTO plain_users (username, psswd) VALUES ('alice','secretalice');");
    checkQuery(tc, cl,"SELECT forumtext from forum WHERE forumid=1",
           {"forumtext"},
           { {"you win!"} } );
    checkQuery(tc, cl,"INSERT INTO forum VALUES (2, 'orphaned text!  everyone should be able to reach')",{}, {});
    checkQuery(tc, cl,"SELECT forumtext from forum WHERE forumid=2",
           {"forumtext"},
           { {"orphaned text!  everyone should be able to reach"} } );
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='alice';",
         "DELETE FROM plain_users WHERE username='alice'");

    //bob
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('bob','secretbob');",
         "INSERT INTO plain_users (username, psswd) VALUES ('bob','secretbob');");
    checkQuery(tc, cl,"SELECT forumtext from forum WHERE forumid=2",
           {"forumtext"},
           { {"orphaned text!  everyone should be able to reach"} } );
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='bob';",
         "DELETE FROM plain_users WHERE username='bob  '");

    //chris
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('chris','secretchris');",
         "INSERT INTO plain_users (username, psswd) VALUES ('chris','secretchris');");
    checkQuery(tc, cl,"SELECT forumtext from forum WHERE forumid=2",
           {"forumtext"},
           { {"orphaned text!  everyone should be able to reach"} } );
    checkQuery(tc, cl,"INSERT INTO groupforum VALUES (2, 2, 20)",{}, {});
    checkQuery(tc, cl,"SELECT forumtext FROM forum, groupforum, usergroup, u WHERE forum.forumid=groupforum.forumid AND groupforum.groupid=usergroup.groupid AND usergroup.userid=u.userid AND u.username='chris' AND groupforum.optionid=20",
           {"forumtext"},
           { {"you win!"},
         {"orphaned text!  everyone should be able to reach"} } );
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='chris';",
         "DELETE FROM plain_users WHERE username='chris'");

    //bob
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('bob','secretbob');",
         "INSERT INTO plain_users (username, psswd) VALUES ('bob','secretbob');");
    checkQuery(tc, cl,"SELECT forumtext FROM forum, groupforum, usergroup, u WHERE forum.forumid=groupforum.forumid AND groupforum.groupid=usergroup.groupid AND usergroup.userid=u.userid AND u.username='bob' AND groupforum.optionid=20",
           {"forumtext"},
           { {"orphaned text!  everyone should be able to reach"} } );
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='bob';",
         "DELETE FROM plain_users WHERE username='bob  '");

    //alice
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('alice','secretalice');",
         "INSERT INTO plain_users (username, psswd) VALUES ('alice','secretalice');");
    checkQuery(tc, cl,"SELECT forumtext FROM forum, groupforum, usergroup, u WHERE forum.forumid=groupforum.forumid AND groupforum.groupid=usergroup.groupid AND usergroup.userid=u.userid AND u.username='alice' AND groupforum.optionid=20",
           {"forumtext"},
           { {"you win!"} } );
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='alice';",
         "DELETE FROM plain_users WHERE username='alice'");

}


static void
UserGroupForum_incFunction(const TestConfig &tc, EDBClient * cl) {
    cl->plain_execute("DROP TABLE IF EXISTS u, usergroup, groupforum, forum, plain_users, pwdcryptdb__users, cryptdb_public, cryptdb_initialized_principals, cryptdb0;");
    assert_res(myCreate(cl,"CREATE TABLE u (userid integer, username givespsswd userid text);",
                      "CREATE TABLE u (userid integer, username text);"),
                         "failed: u table");
    assert_res(myCreate(cl,"CREATE TABLE usergroup (userid equals u.userid hasaccessto groupid integer, groupid integer)",
                      "CREATE TABLE usergroup (userid integer, groupid integer)"), "failed: usergroup table");
    assert_res(myCreate(cl,"CREATE TABLE groupforum (forumid equals forum.forumid integer, groupid equals usergroup.groupid hasaccessto forumid if test(optionid) integer, optionid integer)",
                      "CREATE TABLE groupforum (forumid integer, groupid integer, optionid integer)"), "failed: groupforum table");
    assert_res(myCreate(cl,"CREATE TABLE forum (forumid integer, forumtext encfor forumid text)",
                      "CREATE TABLE forum (forumid integer, forumtext text)"),
                         "failed: forum table");
    cl->plain_execute("DROP FUNCTION IF EXISTS test");
    cl->plain_execute("CREATE FUNCTION test (optionid integer) RETURNS bool RETURN optionid=20");

    assert_res(myCreate(cl,"COMMIT ANNOTATIONS;","CREATE TABLE plain_users (username text, psswd text)"), "problem commiting annotations");

    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('alice','secretalice');","INSERT INTO plain_users (username, psswd) VALUES ('alice','secretalice');");
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('bob','secretbob');","INSERT INTO plain_users (username, psswd) VALUES ('bob','secretbob');");
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('chris','secretchris');","INSERT INTO plain_users (username, psswd) VALUES ('chris','secretchris');");

    //populate things while everyone is logged in
    checkQuery(tc, cl,"INSERT INTO u VALUES (1, 'alice')",{}, {});
    checkQuery(tc, cl,"INSERT INTO u VALUES (2, 'bob')",{}, {});
    checkQuery(tc, cl,"INSERT INTO u VALUES (3, 'chris')",{}, {});

    checkQuery(tc, cl,"INSERT INTO usergroup VALUES (1,1)",{}, {});
    checkQuery(tc, cl,"INSERT INTO usergroup VALUES (2,2)",{}, {});
    checkQuery(tc, cl,"INSERT INTO usergroup VALUES (3,1)",{}, {});
    checkQuery(tc, cl,"INSERT INTO usergroup VALUES (3,2)",{}, {});

    checkQuery(tc, cl,"SELECT * FROM usergroup",
               {"userid", "groupid"},
               { {"1","1"},
                 {"2","2"},
                 {"3","1"},
                 {"3","2"} });

    checkQuery(tc, cl,"INSERT INTO groupforum VALUES (1,1,14)",{}, {});
    checkQuery(tc, cl,"INSERT INTO groupforum VALUES (1,1,20)",{}, {});
    checkQuery(tc, cl,"INSERT INTO groupforum VALUES (1,2,2)",{}, {});
    checkQuery(tc, cl,"INSERT INTO groupforum VALUES (1,2,0)",{}, {});

    checkQuery(tc, cl,"SELECT * FROM groupforum",
           {"forumid","groupid","optionid"},
           { {"1","1","14"},
         {"1","1","20"},
         {"1","2","2"},
         {"1","2","0"} });

    checkQuery(tc, cl,"INSERT INTO forum VALUES (1,'success-- you can see forum text')", {}, {});

    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='alice';",
         "DELETE FROM plain_users WHERE username='alice'");
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='bob';",
         "DELETE FROM plain_users WHERE username='bob'");
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='chris';",
         "DELETE FROM plain_users WHERE username='chris'");

    //alice
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('alice','secretalice');",
         "INSERT INTO plain_users (username, psswd) VALUES ('alice','secretalice');");
    checkQuery(tc, cl,"SELECT forumtext from forum WHERE forumid=1",
           {"forumtext"},
           { {"success-- you can see forum text"} } );
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='alice';",
         "DELETE FROM plain_users WHERE username='alice'");
    
    //bob
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('bob','secretbob');",
         "INSERT INTO plain_users (username, psswd) VALUES ('bob','secretbob');");
    if (tc.stop_if_fail) {
      cerr << "\n\nIn FUNCTION-BASED!!! version of groupsusersforums tests\n\n" << endl;
    }
    testNULL(tc, cl,"SELECT forumtext from forum WHERE forumid=1","");
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='bob';",
         "DELETE FROM plain_users WHERE username='bob'");    

    //chris
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('chris','secretchris');",
         "INSERT INTO plain_users (username, psswd) VALUES ('chris','secretchris');");
    checkQuery(tc, cl,"SELECT forumtext from forum WHERE forumid=1",
           {"forumtext"},
           { {"success-- you can see forum text"} } );
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='chris';",
         "DELETE FROM plain_users WHERE username='chris'");




}


void
TestMultiPrinc::run(const TestConfig &tc, int argc, char ** argv)
{
    EDBClient * cl;
    uint64_t mkey = 113341234;
    string masterKey = BytesFromInt(mkey, AES_KEY_BYTES);

    cl = new EDBClient(tc.host, tc.user, tc.pass, tc.db, 0, true);
    cl->setMasterKey(masterKey);
    cerr << "Test basic..." << endl;
    BasicFunctionality(tc, cl);
    delete cl;

    cl = new EDBClient(tc.host, tc.user, tc.pass, tc.db, 0, true);
    cl->setMasterKey(masterKey);
    cerr << "Test private messages..." << endl;
    PrivMessages(tc, cl);
    delete cl;

    cl = new EDBClient(tc.host, tc.user, tc.pass, tc.db, 0, true);
    cl->setMasterKey(masterKey);
    cerr << "Test user/group/forum..." << endl;
    UserGroupForum(tc, cl);
    delete cl;

    cl = new EDBClient(tc.host, tc.user, tc.pass, tc.db, 0, true);
    cl->setMasterKey(masterKey);
    cerr << "Test user/group/forum including function..." << endl;
    UserGroupForum_incFunction(tc, cl);
    delete cl;

    cerr << "RESULT: " << npass << "/" << ntest << " passed" << endl;
}
