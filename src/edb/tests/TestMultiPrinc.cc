/*
 * TestMultiPrinc
 * -- tests multi principal end-to-end within cryptdb (no proxy tests)
 *
 *
 */

#include "TestMultiPrinc.h"

static int ntest = 0;
static int npass = 0;
static ResType empty;

TestMultiPrinc::TestMultiPrinc()
{

}

TestMultiPrinc::~TestMultiPrinc()
{

}

static void
checkQuery(EDBClient * cl, const string &query, const ResType &expect)
{
    ntest++;
    ResType * test_res = myExecute(cl, query);
    if (!test_res) {
        cerr << "Query: " << query << " cannot execute" << endl;
        if (STOP_IF_FAIL) {
            assert_s(false, "above query could not execute");
        }
        return;
    }

    if (*test_res != expect) {
        cerr << "On query:\n" << query << endl;
        cerr << "we expected resultset:" << endl;
        PrintRes(expect);
        cerr << "but it returned:" << endl;
        PrintRes(*test_res);
        if (STOP_IF_FAIL) {
            assert_s(false, "above query returned incorrect result");
        }
        return;
    }

    npass++;
}

static void
testNULL(EDBClient * cl, const string &annotated, const string &plain) {
  ntest++;
  if (myCreate(cl, annotated, plain)) {
    if (PLAIN) {
      cerr << "Query:\n" << plain << endl;
    } else {
      cerr << "Query:\n" << annotated << endl;
    }
    cerr << "did not return NULL" << endl;
    if (STOP_IF_FAIL) {
      assert_s(false, "above query did not fail (should have)");
    }
    return;
  }
  npass++;
}

static void
BasicFunctionality(EDBClient * cl)
{
    cl->plain_execute(
        "DROP TABLE IF EXISTS u, t1, plain_users, pwdcryptdb__users, cryptdb_publis, cryptdb_initialized_principles, cryptdb0;");
    assert_s(myCreate(
                 cl,
                 "CREATE TABLE t1 (id integer, post encfor id det text, age encfor id ope bigint);",
                 "CREATE TABLE t1 (id integer, post text, age bigint);"),
             "failed (1)");
    assert_s(myCreate(
                 cl,
                 "CREATE TABLE u (id equals t1.id integer, username givespsswd id text);",
                 "CREATE TABLE u (id integer, username text);"),
             "failed (2)");
    assert_s(myCreate(cl,"COMMIT ANNOTATIONS;",
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
    checkQuery(cl,"INSERT INTO u VALUES (1, 'alice')",empty);

    checkQuery(cl, "SELECT * FROM u",
               { {"id", "username"},
                 {"1", "alice"} });

    checkQuery(cl,"INSERT INTO t1 VALUES (1, 'text which is inserted', 23)",
               empty);

    checkQuery(cl,"SELECT * FROM t1",
               { {"id", "post", "age"},
                 {"1", "text which is inserted", "23"} });

    checkQuery(cl,"SELECT post FROM t1 WHERE id = 1 AND age = 23",
               { {"post"},
                 {"text which is inserted"} });

    checkQuery(cl,"UPDATE t1 SET post = 'hello!' WHERE age > 22 AND id = 1",
               empty);

    checkQuery(cl,"SELECT * FROM t1",
               { {"id", "post", "age"},
                 {"1", "hello!", "23"} });

    myCreate(
        cl,"INSERT INTO "+ PWD_TABLE_PREFIX +
        "users (username, psswd) VALUES ('raluca','secretraluca');",
        "INSERT INTO plain_users (username, psswd) VALUES ('raluca','secretraluca');");

    checkQuery(cl,"INSERT INTO u VALUES (2, 'raluca');", empty);

    checkQuery(cl,"SELECT * FROM u",
               { {"id","username"},
                 {"1", "alice"},
                 {"2", "raluca"} });

    checkQuery(cl,"INSERT INTO t1 VALUES (2, 'raluca has text here', 5)",
               empty);

    checkQuery(cl,"SELECT * FROM t1",
               { {"id", "post", "age"},
                 {"1","hello!","23"},
                 {"2","raluca has text here","5"} });

}

static void
PrivMessages(EDBClient * cl)
{
    cl->plain_execute(
        "DROP TABLE IF EXISTS u, msgs, privmsg, plain_users, pwdcryptdb__users, cryptdb_publis, cryptdb_initialized_principles, cryptdb0;");
    assert_s(myCreate(
                 cl,
                 "CREATE TABLE msgs (msgid equals privmsg.msgid integer, msgtext encfor msgid text)",
                 "CREATE TABLE msgs (msgid integer, msgtext text)"),
             "failed: msgs table");
    assert_s(myCreate(
                 cl,
                 "CREATE TABLE privmsg (msgid integer, recid equals u.userid hasaccessto msgid integer, senderid hasaccessto msgid integer)",
                 "CREATE TABLE privmsg (msgid integer, recid integer, senderid integer)"),
             "failed: privmsges table");
    assert_s(myCreate(
                 cl,
                 "CREATE TABLE u (userid equals privmsg.senderid integer, username givespsswd userid text);",
                 "CREATE TABLE u (userid integer, username text);"),
             "failed: u table");
    assert_s(myCreate(cl,"COMMIT ANNOTATIONS;",
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

    checkQuery(cl,"INSERT INTO u VALUES (1, 'alice')",empty);
    checkQuery(cl,"INSERT INTO u VALUES (2, 'bob')",empty);

    checkQuery(
        cl,"INSERT INTO privmsg (msgid, recid, senderid) VALUES (9, 1, 2)",
        empty);
    checkQuery(cl,"INSERT INTO msgs VALUES (1, 'hello world')",empty);

    checkQuery(cl,"SELECT msgtext from msgs WHERE msgid = 1",
               { {"msgtext"},
                 {"hello world"} });
    checkQuery(
        cl,
        "SELECT msgtext from msgs, privmsg, u WHERE username = 'alice' AND userid = recid AND msgs.msgid = privmsg.msgid",
        empty);

    checkQuery(cl,"INSERT INTO msgs VALUES (9, 'message for alice from bob')",
               empty);
    checkQuery(
        cl,
        "SELECT msgtext from msgs, privmsg, u WHERE username = 'alice' AND userid = recid AND msgs.msgid = privmsg.msgid",
        { {"msgtext"},
          {"message for alice from bob"} });

    //TODO: extend this test
}

static void
UserGroupForum(EDBClient * cl) {
    cl->plain_execute("DROP TABLE IF EXISTS u, usergroup, groupforum, forum, plain_users, pwdcryptdb__users, cryptdb_public, cryptdb_initialized_principles, cryptdb0;");
    assert_s(myCreate(cl,"CREATE TABLE u (userid integer, username givespsswd userid text);",
                      "CREATE TABLE u (userid integer, username text);"),
                         "failed: u table");
    assert_s(myCreate(cl,"CREATE TABLE usergroup (userid equals u.userid hasaccessto groupid integer, groupid integer)",
                      "CREATE TABLE usergroup (userid integer, groupid integer)"), "failed: usergroup table");
    assert_s(myCreate(cl,"CREATE TABLE groupforum (forumid equals forum.forumid integer, groupid equals usergroup.groupid hasaccessto forumid integer, optionid integer)",
                      "CREATE TABLE groupforum (forumid integer, groupid integer, optionid integer)"), "failed: groupforum table");
    assert_s(myCreate(cl,"CREATE TABLE forum (forumid integer, forumtext encfor forumid text)",
                      "CREATE TABLE forum (forumid integer, forumtext text)"),
                         "failed: forum table");
    cl->plain_execute("DROP FUNCTION IF EXISTS test");
    cl->plain_execute("CREATE FUNCTION test (optionid integer) RETURNS bool RETURN optionid=20");

    assert_s(myCreate(cl,"COMMIT ANNOTATIONS;","CREATE TABLE plain_users (username text, psswd text)"), "problem commiting annotations");

    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('alice','secretalice');","INSERT INTO plain_users (username, psswd) VALUES ('alice','secretalice');");
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('bob','secretbob');","INSERT INTO plain_users (username, psswd) VALUES ('bob','secretbob');");
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('chris','secretchris');","INSERT INTO plain_users (username, psswd) VALUES ('chris','secretchris');");

    //populate things while everyone is logged in
    checkQuery(cl,"INSERT INTO u VALUES (1, 'alice')",empty);
    checkQuery(cl,"INSERT INTO u VALUES (2, 'bob')",empty);
    checkQuery(cl,"INSERT INTO u VALUES (3, 'chris')",empty);

    checkQuery(cl,"INSERT INTO usergroup VALUES (1,1)",empty);
    checkQuery(cl,"INSERT INTO usergroup VALUES (2,2)",empty);
    checkQuery(cl,"INSERT INTO usergroup VALUES (3,1)",empty);
    checkQuery(cl,"INSERT INTO usergroup VALUES (3,2)",empty);

    checkQuery(cl,"SELECT * FROM usergroup",
               { {"userid", "groupid"},
                 {"1","1"},
                 {"2","2"},
                 {"3","1"},
                 {"3","2"} });

    checkQuery(cl,"INSERT INTO groupforum VALUES (1,1,14)",empty);
    checkQuery(cl,"INSERT INTO groupforum VALUES (1,1,20)",empty);

    return;

    checkQuery(cl,"SELECT * FROM groupforum",
	       { {"forumid","groupid","optionid"},
		 {"1","1","14"},
		 {"1","1","20"} } );

    checkQuery(cl,"INSERT INTO forum VALUES (1,'success-- you can see forum text')",empty);

    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='alice';",
	     "DELETE FROM plain_users WHERE username='alice'");
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='bob';",
	     "DELETE FROM plain_users WHERE username='bob'");
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='chris';",
	     "DELETE FROM plain_users WHERE username='chris'");

    //alice
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('alice','secretalice');",
	     "INSERT INTO plain_users (username, psswd) VALUES ('alice','secretalice');");
    checkQuery(cl,"SELECT forumtext from forum WHERE forumid=1",
	       { {"forumtext"},
		 {"success-- you can see forum text"} } );
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='alice';",
	     "DELETE FROM plain_users WHERE username='alice'");
    
    //bob
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('bob','secretbob');",
	     "INSERT INTO plain_users (username, psswd) VALUES ('bob','secretbob');");
    testNULL(cl,"SELECT forumtext from forum WHERE forumid=1","");
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='bob';",
	     "DELETE FROM plain_users WHERE username='bob'");    

    //chris
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('chris','secretchris');",
	     "INSERT INTO plain_users (username, psswd) VALUES ('chris','secretchris');");
    checkQuery(cl,"SELECT forumtext from forum WHERE forumid=1",
	       { {"forumtext"},
		 {"success-- you can see forum text"} } );
    checkQuery(cl,"UPDATE forum SET forumtext='you win!' WHERE forumid=1",empty);
    checkQuery(cl,"SELECT forumtext from forum WHERE forumid=1",
	       { {"forumtext"},
		 {"you win!"} } );
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='chris';",
	     "DELETE FROM plain_users WHERE username='chris'");    

    //alice
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('alice','secretalice');",
	     "INSERT INTO plain_users (username, psswd) VALUES ('alice','secretalice');");
    checkQuery(cl,"SELECT forumtext from forum WHERE forumid=1",
	       { {"forumtext"},
		 {"you win!"} } );
    checkQuery(cl,"INSERT INTO forum VALUES (2, 'orphaned text!  everyone should be able to reach')",empty);
    checkQuery(cl,"SELECT forumtext from forum WHERE forumid=2",
	       { {"forumtext"},
		 {"orphaned text!  everyone should be able to reach"} } );
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='alice';",
	     "DELETE FROM plain_users WHERE username='alice'");

    //bob
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('bob','secretbob');",
	     "INSERT INTO plain_users (username, psswd) VALUES ('bob','secretbob');");
    checkQuery(cl,"SELECT forumtext from forum WHERE forumid=2",
	       { {"forumtext"},
		 {"orphaned text!  everyone should be able to reach"} } );
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='bob';",
	     "DELETE FROM plain_users WHERE username='bob  '");

    //chris
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('chris','secretchris');",
	     "INSERT INTO plain_users (username, psswd) VALUES ('chris','secretchris');");
    checkQuery(cl,"SELECT forumtext from forum WHERE forumid=2",
	       { {"forumtext"},
		 {"orphaned text!  everyone should be able to reach"} } );
    checkQuery(cl,"INSERT INTO groupforum VALUES (2, 2, 20)",empty);
    checkQuery(cl,"SELECT forumtext FROM forum, groupforum, usergroup, u WHERE forum.forumid=groupforum.forumid AND groupforum.groupid=usergroup.groupid AND usergroup.userid=u.userid AND u.username='chris' AND groupforum.optionid=20",
	       { {"forumtext"},
		 {"you win!"},
		 {"orphaned text!  everyone should be able to reach"} } );
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='chris';",
	     "DELETE FROM plain_users WHERE username='chris'");

    //bob
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('bob','secretbob');",
	     "INSERT INTO plain_users (username, psswd) VALUES ('bob','secretbob');");
    checkQuery(cl,"SELECT forumtext FROM forum, groupforum, usergroup, u WHERE forum.forumid=groupforum.forumid AND groupforum.groupid=usergroup.groupid AND usergroup.userid=u.userid AND u.username='bob' AND groupforum.optionid=20",
	       { {"forumtext"},
		 {"orphaned text!  everyone should be able to reach"} } );
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='bob';",
	     "DELETE FROM plain_users WHERE username='bob  '");

    //alice
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('alice','secretalice');",
	     "INSERT INTO plain_users (username, psswd) VALUES ('alice','secretalice');");
    checkQuery(cl,"SELECT forumtext FROM forum, groupforum, usergroup, u WHERE forum.forumid=groupforum.forumid AND groupforum.groupid=usergroup.groupid AND usergroup.userid=u.userid AND u.username='alice' AND groupforum.optionid=20",
	       { {"forumtext"},
		 {"you win!"} } );
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='alice';",
	     "DELETE FROM plain_users WHERE username='alice'");

}


static void
UserGroupForum_incFunction(EDBClient * cl) {
    cl->plain_execute("DROP TABLE IF EXISTS u, usergroup, groupforum, forum, plain_users, pwdcryptdb__users, cryptdb_public, cryptdb_initialized_principles, cryptdb0;");
    assert_s(myCreate(cl,"CREATE TABLE u (userid integer, username givespsswd userid text);",
                      "CREATE TABLE u (userid integer, username text);"),
                         "failed: u table");
    assert_s(myCreate(cl,"CREATE TABLE usergroup (userid equals u.userid hasaccessto groupid integer, groupid integer)",
                      "CREATE TABLE usergroup (userid integer, groupid integer)"), "failed: usergroup table");
    assert_s(myCreate(cl,"CREATE TABLE groupforum (forumid equals forum.forumid integer, groupid equals usergroup.groupid hasaccessto forumid if test(optionid) integer, optionid integer)",
                      "CREATE TABLE groupforum (forumid integer, groupid integer, optionid integer)"), "failed: groupforum table");
    assert_s(myCreate(cl,"CREATE TABLE forum (forumid integer, forumtext encfor forumid text)",
                      "CREATE TABLE forum (forumid integer, forumtext text)"),
                         "failed: forum table");
    cl->plain_execute("DROP FUNCTION IF EXISTS test");
    cl->plain_execute("CREATE FUNCTION test (optionid integer) RETURNS bool RETURN optionid=20");

    assert_s(myCreate(cl,"COMMIT ANNOTATIONS;","CREATE TABLE plain_users (username text, psswd text)"), "problem commiting annotations");

    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('alice','secretalice');","INSERT INTO plain_users (username, psswd) VALUES ('alice','secretalice');");
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('bob','secretbob');","INSERT INTO plain_users (username, psswd) VALUES ('bob','secretbob');");
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('chris','secretchris');","INSERT INTO plain_users (username, psswd) VALUES ('chris','secretchris');");

    //populate things while everyone is logged in
    checkQuery(cl,"INSERT INTO u VALUES (1, 'alice')",empty);
    checkQuery(cl,"INSERT INTO u VALUES (2, 'bob')",empty);
    checkQuery(cl,"INSERT INTO u VALUES (1, 'chris')",empty);

    checkQuery(cl,"INSERT INTO usergroup VALUES (1,1)",empty);
    checkQuery(cl,"INSERT INTO usergroup VALUES (2,2)",empty);
    checkQuery(cl,"INSERT INTO usergroup VALUES (3,1)",empty);
    checkQuery(cl,"INSERT INTO usergroup VALUES (3,2)",empty);

    checkQuery(cl,"SELECT * FROM usergroup",
               { {"userid", "groupid"},
                 {"1","1"},
                 {"2","2"},
                 {"3","1"},
                 {"3","2"} });

    checkQuery(cl,"INSERT INTO groupforum VALUES (1,1,14)",empty);
    checkQuery(cl,"INSERT INTO groupforum VALUES (1,1,20)",empty);
    checkQuery(cl,"INSERT INTO groupforum VALUES (1,2,2)",empty);
    checkQuery(cl,"INSERT INTO groupforum VALUES (1,2,0)",empty);

    checkQuery(cl,"SELECT * FROM groupforum",
	       { {"forumid","groupid","optionid"},
		 {"1","1","14"},
		 {"1","1","20"},
		 {"1","2","2"},
		 {"1","2","0"} });

    checkQuery(cl,"INSERT INTO forum VALUES (1,'success-- you can see forum text')",empty);

    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='alice';",
	     "DELETE FROM plain_users WHERE username='alice'");
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='bob';",
	     "DELETE FROM plain_users WHERE username='bob'");
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='chris';",
	     "DELETE FROM plain_users WHERE username='chris'");

    //alice
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('alice','secretalice');",
	     "INSERT INTO plain_users (username, psswd) VALUES ('alice','secretalice');");
    checkQuery(cl,"SELECT forumtext from forum WHERE forumid=1",
	       { {"forumtext"},
		 {"success-- you can see forum text"} } );
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='alice';",
	     "DELETE FROM plain_users WHERE username='alice'");
    
    //bob
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('bob','secretbob');",
	     "INSERT INTO plain_users (username, psswd) VALUES ('bob','secretbob');");
    if (STOP_IF_FAIL) {
      cerr << "\n\nIn FUNCTION-BASED!!! version of groupsusersforums tests\n\n" << endl;
    }
    testNULL(cl,"SELECT forumtext from forum WHERE forumid=1","");
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='bob';",
	     "DELETE FROM plain_users WHERE username='bob'");    

    //chris
    myCreate(cl,"INSERT INTO "+ PWD_TABLE_PREFIX + "users (username, psswd) VALUES ('chris','secretchris');",
	     "INSERT INTO plain_users (username, psswd) VALUES ('chris','secretchris');");
    checkQuery(cl,"SELECT forumtext from forum WHERE forumid=1",
	       { {"forumtext"},
		 {"success-- you can see forum text"} } );
    myCreate(cl,"DELETE FROM "+ PWD_TABLE_PREFIX + "users WHERE username='chris';",
	     "DELETE FROM plain_users WHERE username='chris'");




}


void
TestMultiPrinc::run(int argc, char ** argv)
{
    EDBClient * cl;
    uint64_t mkey = 113341234;
    string masterKey = BytesFromInt(mkey, AES_KEY_BYTES);
    assert_s(MULTIPRINC == 1,
             "MULTIPRINCE is off.  Please set it to 1 (in params.h) and run make before attempting this test");

    cl = new EDBClient("localhost", "root", "letmein", "cryptdbtest", masterKey);
    cerr << "Test basic..." << endl;
    BasicFunctionality(cl);
    delete cl;

    cl = new EDBClient("localhost", "root", "letmein", "cryptdbtest", masterKey);
    cerr << "Test private messages..." << endl;
    PrivMessages(cl);
    delete cl;

    cl = new EDBClient("localhost", "root", "letmein", "cryptdbtest", masterKey);
    cerr << "Test user/group/forum..." << endl;
    UserGroupForum(cl);
    delete cl;

    cl = new EDBClient("localhost", "root", "letmein", "cryptdbtest", masterKey);
    cerr << "Test user/group/forum including function..." << endl;
    UserGroupForum_incFunction(cl);
    delete cl;

    cerr << "RESULT: " << npass << "/" << ntest << " passed" << endl;
}
