/*
 * TestQueries.cc
 *  -- end to end query and result test, independant of connection process
 *
 *
 */

#include <stdexcept>
#include <netinet/in.h>

#include <util/errstream.hh>
#include <util/cleanup.hh>
#include <util/cryptdb_log.hh>
#include <test/TestQueries.hh>


using namespace std;

static int ntest = 0;
static int npass = 0;
static test_mode control_type;
static test_mode test_type;
static uint64_t no_conn = 1;
static Connection * control;
static Connection * test;

static QueryList Insert = QueryList("SingleInsert",
    { "CREATE TABLE test_insert (id integer primary key auto_increment, age integer, salary integer, address text, name text)" },
    { "CREATE TABLE test_insert (id integer primary key auto_increment, age enc integer, salary enc integer, address enc text, name text)" },
    { "CREATE TABLE test_insert (id integer primary key auto_increment, age integer, salary integer, address text, name text)" },
    { Query("INSERT INTO test_insert VALUES (1, 21, 100, '24 Rosedale, Toronto, ONT', 'Pat Carlson')", false),
      Query("SELECT * FROM test_insert", false),
      Query("INSERT INTO test_insert (id, age, salary, address, name) VALUES (2, 23, 101, '25 Rosedale, Toronto, ONT', 'Pat Carlson2')", false),
      Query("SELECT * FROM test_insert", false),
      Query("INSERT INTO test_insert (age, address, salary, name, id) VALUES (25, '26 Rosedale, Toronto, ONT', 102, 'Pat2 Carlson', 3)", false),
      Query("SELECT * FROM test_insert", false),
      Query("INSERT INTO test_insert (age, address, salary, name) VALUES (26, 'test address', 30, 'test name')", false),
      Query("SELECT * FROM test_insert", false),
      Query("INSERT INTO test_insert (age, address, salary, name) VALUES (27, 'test address2', 31, 'test name')", false),
      Query("select last_insert_id()", false),
      Query("INSERT INTO test_insert (id) VALUES (7)", false),
      Query("select sum(id) from test_insert", false),
      Query("INSERT INTO test_insert (age) VALUES (40)", false),
      //TODO: proxy has issues with this one...?
      //Query("SELECT age FROM test_insert", false),
      Query("INSERT INTO test_insert (name) VALUES ('Wendy')", false),
      Query("SELECT name FROM test_insert WHERE id=10", false),
      Query("INSERT INTO test_insert (name, address, id, age) VALUES ('Peter Pan', 'first star to the right and straight on till morning', 42, 10)", false),
      Query("SELECT name, address, age FROM test_insert WHERE id=42", false) },
    { "DROP TABLE test_insert" },
    { "DROP TABLE test_insert" },
    { "DROP TABLE test_insert" } );

//migrated from TestSinglePrinc TestSelect
static QueryList Select = QueryList("SingleSelect",
    { "CREATE TABLE test_select (id integer, age integer, salary integer, address text, name text)" },
    { "CREATE TABLE test_select (id integer, age enc integer, salary enc integer, address enc text, name text)" },
    { "CREATE TABLE test_select (id integer, age integer, salary integer, address text, name text)" },
    { Query("INSERT INTO test_select VALUES (1, 10, 0, 'first star to the right and straight on till morning', 'Peter Pan')", false),
      Query("INSERT INTO test_select VALUES (2, 16, 1000, 'Green Gables', 'Anne Shirley')", false),
      Query("INSERT INTO test_select VALUES (3, 8, 0, 'London', 'Lucy')", false),
      Query("INSERT INTO test_select VALUES (4, 10, 0, 'London', 'Edmund')", false),
      Query("INSERT INTO test_select VALUES (5, 30, 100000, '221B Baker Street', 'Sherlock Holmes')", false),
      Query("SELECT * FROM test_select", false),
      Query("SELECT max(id) FROM test_select", false),
      Query("SELECT max(salary) FROM test_select", false),
      Query("SELECT COUNT(*) FROM test_select", false),
      Query("SELECT COUNT(DISTINCT age) FROM test_select", false),
      Query("SELECT COUNT(DISTINCT(address)) FROM test_select", false),
      Query("SELECT name FROM test_select", false),
      Query("SELECT address FROM test_select", false),
      Query("SELECT * FROM test_select WHERE id>3", false),
      Query("SELECT * FROM test_select WHERE age = 8", false),
      Query("SELECT * FROM test_select WHERE salary=15", false),
      Query("SELECT * FROM test_select WHERE age > 10", false),
      Query("SELECT * FROM test_select WHERE age = 10 AND salary = 0", false),
      Query("SELECT * FROM test_select WHERE age = 10 OR salary = 0", false),
      Query("SELECT * FROM test_select WHERE name = 'Peter Pan'", false),
      Query("SELECT * FROM test_select WHERE address='Green Gables'", false),
      Query("SELECT * FROM test_select WHERE address <= '221C'", false),
      Query("SELECT * FROM test_select WHERE address >= 'Green Gables' AND age > 9", false),
      Query("SELECT * FROM test_select WHERE address >= 'Green Gables' OR age > 9", false),
      Query("SELECT * FROM test_select ORDER BY id", false),
      Query("SELECT * FROM test_select ORDER BY salary", false),
      Query("SELECT * FROM test_select ORDER BY name", false),
      Query("SELECT * FROM test_select ORDER BY address", false),
      Query("SELECT sum(age) FROM test_select GROUP BY address ORDER BY address", false),
      Query("SELECT salary, max(id) FROM test_select GROUP BY salary ORDER BY salary", false),
      Query("SELECT * FROM test_select GROUP BY age ORDER BY age", false),
      Query("SELECT * FROM test_select ORDER BY age ASC", false),
      Query("SELECT * FROM test_select ORDER BY address DESC", false),
      Query("SELECT sum(age) as z FROM test_select", false),
      Query("SELECT sum(age) z FROM test_select", false),
      Query("SELECT min(t.id) a FROM test_select AS t", false),
      Query("SELECT t.address AS b FROM test_select t", false) },
    { "DROP TABLE test_select" },
    { "DROP TABLE test_select" },
    { "DROP TABLE test_select" } );

//migrated from TestSinglePrinc TestJoin
static QueryList Join = QueryList("SingleJoin",
    { "CREATE TABLE test_join1 (id integer, age integer, salary integer, address text, name text)",
     "CREATE TABLE test_join2 (id integer, books integer, name text)" },
    { "CREATE TABLE test_join1 (id integer, age enc integer, salary enc integer, address enc text, name text)",
     "CREATE TABLE test_join2 (id integer, books enc integer, name enc text)" },
    { "CREATE TABLE test_join1 (id integer, age integer, salary integer, address text, name text)",
     "CREATE TABLE test_join2 (id integer, books integer, name text)" },
    { Query("INSERT INTO test_join1 VALUES (1, 10, 0, 'first star to the right and straight on till morning','Peter Pan')", false),
      Query("INSERT INTO test_join1 VALUES (2, 16, 1000, 'Green Gables', 'Anne Shirley')", false),
      Query("INSERT INTO test_join1 VALUES (3, 8, 0, 'London', 'Lucy')", false),
      Query("INSERT INTO test_join1 VALUES (4, 10, 0, 'London', 'Edmund')", false),
      Query("INSERT INTO test_join1 VALUES (5, 30, 100000, '221B Baker Street', 'Sherlock Holmes')", false),
      Query("INSERT INTO test_join2 VALUES (1, 6, 'Peter Pan')", false),
      Query("INSERT INTO test_join2 VALUES (2, 8, 'Anne Shirley')", false),
      Query("INSERT INTO test_join2 VALUES (3, 7, 'Lucy')", false),
      Query("INSERT INTO test_join2 VALUES (4, 7, 'Edmund')", false),
      Query("INSERT INTO test_join2 VALUES (10, 4, '221B Baker Street')", false),
      Query("SELECT address FROM test_join1, test_join2 WHERE test_join1.id=test_join2.id", false),
      Query("SELECT test_join1.id, test_join2.id, age, books, test_join2.name FROM test_join1, test_join2 WHERE test_join1.id = test_join2.id", false),
      Query("SELECT test_join1.name, age, salary, test_join2.name, books FROM test_join1, test_join2 WHERE test_join1.age=test_join2.books", false),
      //we don't support things that join unecrypted columns to encrypted columns
      //Query("SELECT * FROM test_join1, test_join2 WHERE test_join1.name=test_join2.name", false),
      Query("SELECT * FROM test_join1, test_join2 WHERE test_join1.address=test_join2.name", false),
      Query("SELECT address FROM test_join1 AS a, test_join2 WHERE a.id=test_join2.id", false),
      Query("SELECT a.id, b.id, age, books, b.name FROM test_join1 a, test_join2 AS b WHERE a.id=b.id", false),
      Query("SELECT test_join1.name, age, salary, b.name, books FROM test_join1, test_join2 b WHERE test_join1.age = b.books", false) },
    { "DROP TABLE test_join1",
     "DROP TABLE test_join2" },
    { "DROP TABLE test_join1",
     "DROP TABLE test_join2" },
    { "DROP TABLE test_join1",
     "DROP TABLE test_join2" } );

//migrated from TestSinglePrinc TestUpdate
static QueryList Update = QueryList("SingleUpdate",
    { "CREATE TABLE test_update (id integer, age integer, salary integer, address text, name text)" },
    { "CREATE TABLE test_update (id integer, age enc integer, salary enc integer, address enc text, name enc text)" },
    { "CREATE TABLE test_update (id integer, age integer, salary integer, address text, name text)" },
    { Query("INSERT INTO test_update VALUES (1, 10, 0, 'first star to the right and straight on till morning','Peter Pan')", false),
      Query("INSERT INTO test_update VALUES (2, 16, 1000, 'Green Gables', 'Anne Shirley')", false),
      Query("INSERT INTO test_update VALUES (3, 8, 0, 'London', 'Lucy')", false),
      Query("INSERT INTO test_update VALUES (4, 10, 0, 'London', 'Edmund')", false),
      Query("INSERT INTO test_update VALUES (5, 30, 100000, '221B Baker Street', 'Sherlock Holmes')", false),
      Query("INSERT INTO test_update VALUES (6, 11, 0 , 'hi', 'no one')", false),
      Query("UPDATE test_update SET salary=0", false),
      Query("SELECT * FROM test_update", false),
      Query("UPDATE test_update SET age=21 WHERE id = 6", false),
      Query("SELECT * FROM test_update", false),
      Query("UPDATE test_update SET address='Pemberly', name='Elizabeth Darcy' WHERE id=6", false),
      Query("SELECT * FROM test_update", false),
      Query("UPDATE test_update SET salary=55000 WHERE age=30", false),
      Query("SELECT * FROM test_update", false),
      Query("UPDATE test_update SET salary=20000 WHERE address='Pemberly'", false),
      Query("SELECT * FROM test_update", false),
      Query("SELECT age FROM test_update WHERE age > 20", false),
      Query("SELECT id FROM test_update", false),
      Query("SELECT sum(age) FROM test_update", false),
      Query("UPDATE test_update SET age=20 WHERE name='Elizabeth Darcy'", false),
      Query("SELECT * FROM test_update WHERE age > 20", false),
      Query("SELECT sum(age) FROM test_update", false),
      Query("UPDATE test_update SET age = age + 2", false),
      Query("SELECT age FROM test_update", false),
      Query("UPDATE test_update SET id = id + 10, salary = salary + 19, name = 'xxx', address = 'foo' WHERE address = 'London'", false),
      Query("SELECT * FROM test_update", false),
      Query("SELECT * FROM test_update WHERE address < 'fml'", false),
      Query("UPDATE test_update SET address = 'Neverland' WHERE id=1", false),
      Query("SELECT * FROM test_update", false) },
    { "DROP TABLE test_update" },
    { "DROP TABLE test_update" },
    { "DROP TABLE test_update" } );


//migrated from TestDelete
static QueryList Delete = QueryList("SingleDelete",
    { "CREATE TABLE test_delete (id integer, age integer, salary integer, address text, name text)" },
    { "CREATE TABLE test_delete (id integer, age enc integer, salary enc integer, address enc text, name enc text)" },
    { "CREATE TABLE test_delete (id integer, age integer, salary integer, address text, name text)" },
    { Query("INSERT INTO test_delete VALUES (1, 10, 0, 'first star to the right and straight on till morning','Peter Pan')", false),
      Query("INSERT INTO test_delete VALUES (2, 16, 1000, 'Green Gables', 'Anne Shirley')", false),
      Query("INSERT INTO test_delete VALUES (3, 8, 0, 'London', 'Lucy')", false),
      Query("INSERT INTO test_delete VALUES (4, 10, 0, 'London', 'Edmund')", false),
      Query("INSERT INTO test_delete VALUES (5, 30, 100000, '221B Baker Street', 'Sherlock Holmes')", false),
      Query("INSERT INTO test_delete VALUES (6, 21, 2000, 'Pemberly', 'Elizabeth')", false),
      Query("INSERT INTO test_delete VALUES (7, 10000, 1, 'Mordor', 'Sauron')", false),
      Query("INSERT INTO test_delete VALUES (8, 25, 100, 'The Heath', 'Eustacia Vye')", false),
      Query("DELETE FROM test_delete WHERE id=1", false),
      Query("SELECT * FROM test_delete", false),
      Query("DELETE FROM test_delete WHERE age=30", false),
      Query("SELECT * FROM test_delete", false),
      Query("DELETE FROM test_delete WHERE name='Eustacia Vye'", false),
      Query("SELECT * FROM test_delete", false),
      Query("DELETE FROM test_delete WHERE address='London'", false),
      Query("SELECT * FROM test_delete", false),
      Query("DELETE FROM test_delete WHERE salary = 1", false),
      Query("SELECT * FROM test_delete", false),
      Query("INSERT INTO test_delete VALUES (1, 10, 0, 'first star to the right and straight on till morning','Peter Pan')", false),
      Query("SELECT * FROM test_delete", false),
      Query("DELETE FROM test_delete", false),
      Query("SELECT * FROM test_delete", false) },
    { "DROP TABLE test_delete" },
    { "DROP TABLE test_delete" },
    { "DROP TABLE test_delete" } );

//migrated from TestSearch
static QueryList Search = QueryList("SingleSearch",
    { "CREATE TABLE test_search (id integer, searchable text)" },
    { "CREATE TABLE test_search (id integer, searchable enc search text)" },
    { "CREATE TABLE test_search (id integer, searchable text)" },
    { Query("INSERT INTO test_search VALUES (1, 'short text')", false),
      Query("INSERT INTO test_search VALUES (2, 'Text with CAPITALIZATION')", false),
      Query("INSERT INTO test_search VALUES (3, '')", false),
      Query("INSERT INTO test_search VALUES (4, 'When I have fears that I may cease to be, before my pen has gleaned my teeming brain; before high piled books in charactery hold like ruch garners the full-ripened grain. When I behold on the nights starred face huge cloudy symbols of high romance and think that I may never live to trace their shadows with the magic hand of chance; when I feel fair creature of the hour that I shall never look upon thee more, never have relish of the faerie power of unreflecting love, I stand alone on the edge of the wide world and think till love and fame to nothingness do sink')", false),
      Query("SELECT * FROM test_search WHERE searchable LIKE '%text%'", false),
      Query("SELECT * FROM test_search WHERE searchable LIKE 'short%'", false),
      Query("SELECT * FROM test_search WHERE searchable LIKE ''", false),
      Query("SELECT * FROM test_search WHERE searchable LIKE '%capitalization'", false),
      Query("SELECT * FROM test_search WHERE searchable LIKE 'noword'", false),
      Query("SELECT * FROM test_search WHERE searchable LIKE 'when%'", false),
      Query("SELECT * FROM test_search WHERE searchable < 'slow'", false),
      Query("UPDATE test_search SET searchable='text that is new' WHERE id=1", false),
      Query("SELECT * FROM test_search WHERE searchable < 'slow'", false) },
    { "DROP TABLE test_search" },
    { "DROP TABLE test_search" },
    { "DROP TABLE test_search" } );

static QueryList Basic = QueryList("MultiBasic",
    { "CREATE TABLE t1 (id integer, post text, age bigint)",
      "CREATE TABLE u_basic (id integer, username text)",
      "CREATE TABLE "+PWD_TABLE_PREFIX+"u_basic (username text, psswd text)" },
    { "CREATE TABLE t1 (id integer, post text, age bigint)",
      "CREATE TABLE u_basic (id integer, username text)",
      "CREATE TABLE "+PWD_TABLE_PREFIX+"u_basic (username text, psswd text)" },
    { "CREATE TABLE t1 (id integer, post encfor id det text, age encfor id ope bigint)",
      "CREATE TABLE u_basic (id equals t1.id integer, username givespsswd id text)",
      "COMMIT ANNOTATIONS" },
    { Query("INSERT INTO "+PWD_TABLE_PREFIX+"u_basic (username, psswd) VALUES ('alice', 'secretalice')", false),
      Query("DELETE FROM "+PWD_TABLE_PREFIX+"u_basic WHERE username='alice'", false),
      Query("INSERT INTO "+PWD_TABLE_PREFIX+"u_basic (username, psswd) VALUES ('alice', 'secretalice')", false),
      Query("INSERT INTO u_basic VALUES (1, 'alice')", false),
      Query("SELECT * FROM u_basic", false),
      Query("INSERT INTO t1 VALUES (1, 'text which is inserted', 23)", false),
      Query("SELECT * FROM t1", false),
      Query("SELECT post from t1 WHERE id = 1 AND age = 23", false),
      Query("UPDATE t1 SET post='hello!' WHERE age > 22 AND id =1", false),
      Query("SELECT * FROM t1", false),
      Query("INSERT INTO "+PWD_TABLE_PREFIX+"u_basic (username, psswd) VALUES ('raluca','secretraluca')", false),
      Query("INSERT INTO u_basic VALUES (2, 'raluca')", false),
      Query("SELECT * FROM u_basic", false),
      Query("INSERT INTO t1 VALUES (2, 'raluca has text here', 5)", false),
      Query("SELECT * FROM t1", false) },
    { "DROP TABLE u_basic",
      "DROP TABLE t1",
      "DROP TABLE "+PWD_TABLE_PREFIX+"u_basic" },
    { "DROP TABLE u_basic",
      "DROP TABLE t1",
      "DROP TABLE "+PWD_TABLE_PREFIX+"u_basic" },
    { "DROP TABLE u_basic",
      "DROP TABLE t1",
      "" } );

//migrated from PrivMessages
static QueryList PrivMessages = QueryList("MultiPrivMessages",
    { "CREATE TABLE msgs (msgid integer, msgtext text)",
      "CREATE TABLE privmsg (msgid integer, recid integer, senderid integer)",
      "CREATE TABLE u_mess (userid integer, username text)",
      "CREATE TABLE "+PWD_TABLE_PREFIX+"u_mess (username text, psswd text)" },
    { "CREATE TABLE msgs (msgid integer, msgtext text)",
      "CREATE TABLE privmsg (msgid integer, recid integer, senderid integer)",
      "CREATE TABLE u_mess (userid integer, username text)",
      "CREATE TABLE "+PWD_TABLE_PREFIX+"u_mess (username text, psswd text)" },
    { "CREATE TABLE msgs (msgid equals privmsg.msgid integer, msgtext encfor msgid text)",
      "CREATE TABLE privmsg (msgid integer, recid equals u_mess.userid speaksfor msgid integer, senderid speaksfor msgid integer)",
      "CREATE TABLE u_mess (userid equals privmsg.senderid integer, username givespsswd userid text)",
      "COMMIT ANNOTATIONS" },
    { Query("INSERT INTO "+PWD_TABLE_PREFIX+"u_mess (username, psswd) VALUES ('alice', 'secretalice')", false),
      Query("INSERT INTO "+PWD_TABLE_PREFIX+"u_mess (username, psswd) VALUES ('bob', 'secretbob')", false),
      Query("INSERT INTO u_mess VALUES (1, 'alice')", false),
      Query("INSERT INTO u_mess VALUES (2, 'bob')", false),
      Query("INSERT INTO privmsg (msgid, recid, senderid) VALUES (9, 1, 2)", false),
      Query("INSERT INTO msgs VALUES (1, 'hello world')", false),
      Query("SELECT msgtext FROM msgs WHERE msgid=1", false),
      Query("SELECT msgtext FROM msgs, privmsg, u_mess WHERE username = 'alice' AND userid = recid AND msgs.msgid = privmsg.msgid", false),
      Query("INSERT INTO msgs VALUES (9, 'message for alice from bob')", false),
      Query("SELECT msgtext FROM msgs, privmsg, u_mess WHERE username = 'alice' AND userid = recid AND msgs.msgid = privmsg.msgid", false) },
    { "DROP TABLE msgs",
      "DROP TABLE privmsg",
      "DROP TABLE u_mess",
      "DROP TABLE "+PWD_TABLE_PREFIX+"u_mess" },
    { "DROP TABLE msgs",
      "DROP TABLE privmsg",
      "DROP TABLE u_mess",
      "DROP TABLE "+PWD_TABLE_PREFIX+"u_mess" },
    { "DROP TABLE msgs",
      "DROP TABLE privmsg",
      "DROP TABLE u_mess",
      "" } );

//migrated from UserGroupForum
static QueryList UserGroupForum = QueryList("UserGroupForum",
    { "CREATE TABLE u (userid integer, username text)",
      "CREATE TABLE usergroup (userid integer, groupid integer)",
      "CREATE TABLE groupforum (forumid integer, groupid integer, optionid integer)",
      "CREATE TABLE forum (forumid integer, forumtext text)",
      "CREATE TABLE "+PWD_TABLE_PREFIX+"u (username text, psswd text)" },
    { "CREATE TABLE u (userid integer, username text)",
      "CREATE TABLE usergroup (userid integer, groupid integer)",
      "CREATE TABLE groupforum (forumid integer, groupid integer, optionid integer)",
      "CREATE TABLE forum (forumid integer, forumtext text)",
      "CREATE TABLE "+PWD_TABLE_PREFIX+"u (username text, psswd text)" },
    { "CREATE TABLE u (userid integer, username givespsswd userid text)",
      "CREATE TABLE usergroup (userid equals u.userid speaksfor groupid integer, groupid integer)",
      "CREATE TABLE groupforum (forumid equals forum.forumid integer, groupid equals usergroup.groupid speaksfor forumid if test(optionid) integer, optionid integer)",
      "CREATE TABLE forum (forumid integer, forumtext encfor forumid det text)",
      "COMMIT ANNOTATIONS" },
    { Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('alice', 'secretalice')", false),
      Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('bob', 'secretbob')", false),
      Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('chris', 'secretchris')", false),

      //Alice, Bob, Chris all logged on

      Query("INSERT INTO u VALUES (1, 'alice')", false),
      Query("INSERT INTO u VALUES (2, 'bob')", false),
      Query("INSERT INTO u VALUES (3, 'chris')", false),

      Query("INSERT INTO usergroup VALUES (1,1)", false),
      Query("INSERT INTO usergroup VALUES (2,2)", false),
      Query("INSERT INTO usergroup VALUES (3,1)", false),
      Query("INSERT INTO usergroup VALUES (3,2)", false),

      //Alice is in group 1, Bob in group 2, Chris in group 1 & group 2

      Query("SELECT * FROM usergroup", false),
      Query("INSERT INTO groupforum VALUES (1,1,14)", false),
      Query("INSERT INTO groupforum VALUES (1,1,20)", false),

      //Group 1 has access to forum 1

      Query("SELECT * FROM groupforum", false),
      Query("INSERT INTO forum VALUES (1, 'sucess-- you can see forum text')", false),
      Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='alice'", false),
      Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='bob'", false),
      Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='chris'", false),

      //All users logged off at this point

      //alice
      Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('alice', 'secretalice')", false),
      //only Alice logged in and she should see forum 1
      Query("SELECT forumtext FROM forum WHERE forumid=1", false),
      Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='alice'", false),


      //bob
      Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('bob', 'secretbob')", false),
      //only Bob logged in and he should not see forum 1
      Query("SELECT forumtext FROM forum WHERE forumid=1",true),
      Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='bob'", false),


      //chris
      Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('chris', 'secretchris')",false),
      //only Chris logged in and he should see forum 1
      Query("SELECT forumtext FROM forum WHERE forumid=1",false),
      //change forum text while Chris logged in
      Query("UPDATE forum SET forumtext='you win!' WHERE forumid=1",false),
      Query("SELECT forumtext FROM forum WHERE forumid=1",false),
      Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='chris'",false),


      //alice
      Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('alice','secretalice')",false),
      //only Alice logged in and she should see new text in forum 1
      Query("SELECT forumtext FROM forum WHERE forumid=1",false),
      //create an orphaned forum
      Query("INSERT INTO forum VALUES (2, 'orphaned text! everyone should be able to see me')",false),
      //only Alice logged in and she should see text in orphaned forum 2                       
      Query("SELECT forumtext FROM forum WHERE forumid=2",false),
      Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='alice'",false),


      //bob
      Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('bob', 'secretbob')",false),
      //only Bob logged in and he should see text in orphaned forum 2
      Query("SELECT forumtext FROM forum WHERE forumid=2",false),
      Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='bob'",false),


      //chris
      Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('chris','secretchris')",false),
      //only Chris logged in and he should see text in orphaned forum 2
      Query("SELECT forumtext FROM forum WHERE forumid=2",false),
      //de-orphanize forum 2 -- now only accessible by group 2
      Query("INSERT INTO groupforum VALUES (2,2,20)",false),
      //only Chris logged in and he should see text in both forum 1 and forum 2
      Query("SELECT forumtext FROM forum AS f, groupforum AS g, usergroup AS ug, u WHERE f.forumid=g.forumid AND g.groupid=ug.groupid AND ug.userid=u.userid AND u.username='chris' AND g.optionid=20",false),
      Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='chris'",false),


      //bob
      Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('bob','secretbob')",false),
      //only Bob logged in and he should see text in forum 2
      Query("SELECT forumtext FROM forum AS f, groupforum AS g, usergroup AS ug, u WHERE f.forumid=g.forumid AND g.groupid=ug.groupid AND ug.userid=u.userid AND u.username='bob' AND g.optionid=20",false),
      Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='bob'",false),


      //alice
      Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('alice','secretalice')",false),
      //only Alice logged in and she should see text in forum 1
      Query("SELECT forumtext FROM forum AS f, groupforum AS g, usergroup AS ug, u WHERE f.forumid=g.forumid AND g.groupid=ug.groupid AND ug.userid=u.userid AND u.username='alice' AND g.optionid=20",false),
      Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='alice'",false),

      //all logged out at this point

      //give group 2 access to forum 1 with the wrong access IDs -- since the forum will be inaccessible to group 2, doesn't matter that no one is logged in
      Query("INSERT INTO groupforum VALUES (1,2,2)", false),
      Query("INSERT INTO groupforum VALUES (1,2,0)", false),
      //attempt to gice group 2 actual access to the forum -- should fail, because no one is logged in
      Query("INSERT INTO groupforum VALUES (1,2,20)", true),


      //bob
      Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('bob', 'secretbob')",false),
      //only Bob logged in and he should still not have access to forum 1
      Query("SELECT forumtext FROM forum WHERE forumid=1",true),
      Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='bob'",false)},
    { "DROP TABLE u",
      "DROP TABLE usergroup",
      "DROP TABLE groupforum",
      "DROP TABLE forum",
      "DROP TABLE "+PWD_TABLE_PREFIX+"u" },
    { "DROP TABLE u",
      "DROP TABLE usergroup",
      "DROP TABLE groupforum",
      "DROP TABLE forum",
      "DROP TABLE "+PWD_TABLE_PREFIX+"u" },
    { "DROP TABLE u",
      "DROP TABLE usergroup",
      "DROP TABLE groupforum",
      "DROP TABLE forum",
      "" } );

static QueryList Auto = QueryList("AutoInc",
    { "CREATE TABLE msgs (msgid integer PRIMARY KEY AUTO_INCREMENT, msgtext text)",
      "CREATE TABLE privmsg (msgid integer, recid integer, senderid integer)",
      "CREATE TABLE u_auto (userid integer, username text)",
      "CREATE TABLE "+PWD_TABLE_PREFIX+"u_auto (username text, psswd text)" },
    { "CREATE TABLE msgs (msgid integer PRIMARY KEY AUTO_INCREMENT, msgtext enc text)",
      "CREATE TABLE privmsg (msgid integer, recid enc integer, senderid enc integer)",
      "CREATE TABLE u_auto (userid enc integer, username enc text)",
      "CREATE TABLE "+PWD_TABLE_PREFIX+"u_auto (username text, psswd text)" },
    { "CREATE TABLE msgs (msgid equals privmsg.msgid integer AUTO_INCREMENT PRIMARY KEY , msgtext encfor msgid text)",
      "CREATE TABLE privmsg (msgid integer, recid equals u_auto.userid speaksfor msgid integer, senderid speaksfor msgid integer)",
      "CREATE TABLE u_auto (userid equals privmsg.senderid integer, username givespsswd userid text)",
      "COMMIT ANNOTATIONS" },
    { Query("INSERT INTO "+PWD_TABLE_PREFIX+"u_auto (username, psswd) VALUES ('alice','secretA')",false),
      Query("INSERT INTO "+PWD_TABLE_PREFIX+"u_auto (username, psswd) VALUES ('bob','secretB')",false),
      Query("INSERT INTO u_auto VALUES (1, 'alice')",false),
      Query("INSERT INTO u_auto VALUES (2, 'bob')",false),
      Query("INSERT INTO privmsg (msgid, recid, senderid) VALUES (9, 1, 2)", false),
      Query("INSERT INTO msgs (msgtext) VALUES ('hello world')", false),
      Query("INSERT INTO msgs (msgtext) VALUES ('hello world2')", false),
      Query("INSERT INTO msgs (msgtext) VALUES ('hello world3')", false),
      Query("SELECT msgtext FROM msgs WHERE msgid=1", false),
      Query("SELECT msgtext FROM msgs WHERE msgid=2", false),
      Query("SELECT msgtext FROM msgs WHERE msgid=3", false),
      Query("SELECT msgtext FROM msgs, privmsg, u_auto WHERE username = 'alice' AND userid = recid AND msgs.msgid = privmsg.msgid", false),
      Query("INSERT INTO msgs VALUES (9, 'message for alice from bob')", false),
      Query("SELECT msgtext FROM msgs, privmsg, u_auto WHERE username = 'alice' AND userid = recid AND msgs.msgid = privmsg.msgid", false) },
    { "DROP TABLE msgs",
      "DROP TABLE privmsg",
      "DROP TABLE u_auto",
      "DROP TABLE "+PWD_TABLE_PREFIX+"u_auto" },
    { "DROP TABLE msgs",
      "DROP TABLE privmsg",
      "DROP TABLE u_auto",
      "DROP TABLE "+PWD_TABLE_PREFIX+"u_auto" },
    { "DROP TABLE msgs",
      "DROP TABLE privmsg",
      "DROP TABLE u_auto",
      ""} );

static QueryList Null = QueryList("Null",
    { "CREATE TABLE test_null (uid integer, age integer, address text)",
      "CREATE TABLE u_null (uid integer, username text)",
      "CREATE TABLE "+PWD_TABLE_PREFIX+"u_null (username text, password text)"},
    { "CREATE TABLE test_null (uid integer, age enc integer, address enc text)",
      "CREATE TABLE u_null (uid integer, username text)",
      "CREATE TABLE "+PWD_TABLE_PREFIX+"u_null (username text, password enc text)"},
    //can only handle NULL's on non-principal fields
    { "CREATE TABLE test_null (uid integer, age integer, address text)",
      "CREATE TABLE u_null (uid equals test_null.uid integer, username givespsswd uid text)",
      "COMMIT ANNOTATIONS"},                                  
    { Query("INSERT INTO "+PWD_TABLE_PREFIX+"u_null (username, password) VALUES ('alice', 'secretA')", false),
      Query("INSERT INTO u_null VALUES (1, 'alice')",false),
      Query("INSERT INTO test_null (uid, age) VALUES (1, 20)",false),
      Query("SELECT * FROM test_null",false),
      Query("INSERT INTO test_null (uid, address) VALUES (1, 'somewhere over the rainbow')",false),
      Query("SELECT * FROM test_null",false),
      Query("INSERT INTO test_null (uid, age) VALUES (1, NULL)", false),
      Query("SELECT * FROM test_null",false),
      Query("INSERT INTO test_null (uid, address) VALUES (1, NULL)", false),
      Query("SELECT * FROM test_null",false),
      Query("INSERT INTO test_null VALUES (1, 25, 'Australia')",false),
      Query("SELECT * FROM test_null",false) },
    { "DROP TABLE test_null",
      "DROP TABLE u_null",
      "DROP TABLE "+PWD_TABLE_PREFIX+"u_null" },
    { "DROP TABLE test_null",
      "DROP TABLE u_null",
      "DROP TABLE "+PWD_TABLE_PREFIX+"u_null" },
    { "DROP TABLE test_null",
      "DROP TABLE u_null",
      "" } );

static QueryList ManyConnections = QueryList("Multiple connections",
    { "CREATE TABLE msgs (msgid integer PRIMARY KEY AUTO_INCREMENT, msgtext text)",
      "CREATE TABLE privmsg (msgid integer, recid integer, senderid integer)",
      "CREATE TABLE forum (forumid integer AUTO_INCREMENT PRIMARY KEY, title text)",
      "CREATE TABLE post (postid integer AUTO_INCREMENT PRIMARY KEY, forumid integer, posttext text, author integer)",
      "CREATE TABLE u_conn (userid integer, username text)",
      "CREATE TABLE "+PWD_TABLE_PREFIX+"u_conn (username text, psswd text)" },
    { "CREATE TABLE msgs (msgid integer PRIMARY KEY AUTO_INCREMENT, msgtext enc text)",
      "CREATE TABLE privmsg (msgid integer, recid enc integer, senderid enc integer)",
      "CREATE TABLE forum (forumid integer AUTO_INCREMENT PRIMARY KEY, title enc text)",
      "CREATE TABLE post (postid integer AUTO_INCREMENT PRIMARY KEY, forumid integer, posttext enc text, author integer)",
      "CREATE TABLE u_conn (userid enc integer, username enc text)",
      "CREATE TABLE "+PWD_TABLE_PREFIX+"u_conn (username text, psswd text)" },
    { "CREATE TABLE msgs (msgid equals privmsg.msgid integer AUTO_INCREMENT PRIMARY KEY , msgtext encfor msgid text)",
      "CREATE TABLE privmsg (msgid integer, recid equals u_conn.userid speaksfor msgid integer, senderid speaksfor msgid integer)",
      "CREATE TABLE forum (forumid integer AUTO_INCREMENT PRIMARY KEY, title text)",
      "CREATE TABLE post (postid integer AUTO_INCREMENT PRIMARY KEY, forumid equals forum.forumid integer, posttext encfor forumid text, author equals u_conn.userid speaksfor forumid integer)",
      "CREATE TABLE u_conn (userid equals privmsg.senderid integer, username givespsswd userid text)",
      "COMMIT ANNOTATIONS" },
    { Query("INSERT INTO "+PWD_TABLE_PREFIX+"u_conn (username, psswd) VALUES ('alice','secretA')",false),
      Query("INSERT INTO "+PWD_TABLE_PREFIX+"u_conn (username, psswd) VALUES ('bob','secretB')",false),
      Query("INSERT INTO u_conn VALUES (1, 'alice')",false),
      Query("INSERT INTO u_conn VALUES (2, 'bob')",false),
      Query("INSERT INTO privmsg (msgid, recid, senderid) VALUES (9, 1, 2)", false),
      Query("SELECT LAST_INSERT_ID()",false),
      Query("INSERT INTO forum (title) VALUES ('my first forum')", false),
      Query("SELECT LAST_INSERT_ID()",false),
      Query("INSERT INTO forum (title) VALUES ('my first forum')", false),
      Query("SELECT LAST_INSERT_ID()",false),
      Query("INSERT INTO forum VALUES (11, 'testtest')",false),
      Query("INSERT INTO post (forumid, posttext, author) VALUES (1,'first post in first forum!', 1)",false),
      Query("SELECT LAST_INSERT_ID()",false),
      Query("INSERT INTO msgs (msgtext) VALUES ('hello world')", false),
      Query("SELECT LAST_INSERT_ID()",false),
      Query("INSERT INTO forum (title) VALUES ('two fish')", false),
      Query("INSERT INTO post (forumid, posttext, author) VALUES (12,'red fish',2)", false),
      Query("INSERT INTO post (forumid, posttext, author) VALUES (12,'blue fish',1)", false),
      Query("SELECT LAST_INSERT_ID()",false),
      Query("INSERT INTO msgs (msgtext) VALUES ('hello world2')", false),
      Query("SELECT LAST_INSERT_ID()",false),
      Query("INSERT INTO post (forumid, posttext, author) VALUES (12,'black fish, blue fish',1)", false),
      Query("INSERT INTO post (forumid, posttext, author) VALUES (12,'old fish, new fish',2)", false),
      Query("SELECT LAST_INSERT_ID()",false),
      Query("INSERT INTO msgs (msgtext) VALUES ('hello world3')", false),
      Query("SELECT LAST_INSERT_ID()",false),
      Query("SELECT msgtext FROM msgs WHERE msgid=1", false),
      Query("SELECT * FROM forum",false),
      Query("SELECT msgtext FROM msgs WHERE msgid=2", false),
      Query("SELECT msgtext FROM msgs WHERE msgid=3", false),
      Query("SELECT post.* FROM post, forum WHERE post.forumid = forum.forumid AND forum.title = 'two fish'",false),
      Query("SELECT msgtext FROM msgs, privmsg, u_conn WHERE username = 'alice' AND userid = recid AND msgs.msgid = privmsg.msgid", false),
      Query("INSERT INTO msgs VALUES (9, 'message for alice from bob')", false),
            //Query("SELECT LAST_INSERT_ID()",false),
      Query("SELECT msgtext FROM msgs, privmsg, u_conn WHERE username = 'alice' AND userid = recid AND msgs.msgid = privmsg.msgid", false) },
    { "DROP TABLE msgs",
      "DROP TABLE privmsg",
      "DROP TABLE forum",
      "DROP TABLE post",
      "DROP TABLE u_conn",
      "DROP TABLE "+PWD_TABLE_PREFIX+"u_conn" },
    { "DROP TABLE msgs",
      "DROP TABLE privmsg",
      "DROP TABLE forum",
      "DROP TABLE post",
      "DROP TABLE u_conn",
      "DROP TABLE "+PWD_TABLE_PREFIX+"u_conn" },
    { "DROP TABLE msgs",
      "DROP TABLE privmsg",
      "DROP TABLE forum",
      "DROP TABLE post",
      "DROP TABLE u_conn",
      ""} );
    



//-----------------------------------------------------------------------

Connection::Connection(const TestConfig &input_tc, test_mode input_type) {
    tc = input_tc;
    type = input_type;
    cl = 0;
    proxy_pid = -1;

    try {
        start();
    } catch (...) {
        stop();
        throw;
    }
}


Connection::~Connection() {
    stop();
}

void
Connection::restart() {
    stop();
    start();
}

static bool
try_connect_localhost(uint port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(port);
    int r = connect(fd, (struct sockaddr *) &sin, sizeof(sin));
    close(fd);

    if (r == 0)
        return true;
    else
        return false;
}

static uint
alloc_port()
{
    static uint port = 5121;
    for (;;) {
        int myport = port++;
        if (!try_connect_localhost(myport))
            return myport;
    }
}

void
Connection::start() {
    uint64_t mkey = 1133421234;
    string masterKey = BytesFromInt(mkey, AES_KEY_BYTES); 
    switch (type) {
        //plain -- new connection straight to the DB
    case UNENCRYPTED:
    {
        Connect * c = new Connect(tc.host, tc.user, tc.pass, tc.db, tc.port);
        conn_set.insert(c);
        this->conn = conn_set.begin();
        break;
    }
        //single -- new EDBProxy
    case SINGLE:
        cl = new EDBProxy(tc.host, tc.user, tc.pass, tc.db, tc.port, false);
        cl->setMasterKey(masterKey);
        break;
        //multi -- new EDBProxy
    case MULTI:
        cl = new EDBProxy(tc.host, tc.user, tc.pass, tc.db, tc.port, true);
        cl->setMasterKey(masterKey);
        assert_s(cl->plain_execute("DROP FUNCTION IF EXISTS test").ok, "dropping test for multi");
        assert_s(cl->plain_execute("CREATE FUNCTION test (optionid integer) RETURNS bool RETURN optionid=20").ok, "creating test function for multi");
        break;
        //proxy -- start proxy in separate process and initialize connection
    case PROXYPLAIN:
    case PROXYSINGLE:
    case PROXYMULTI:
        tc.port = alloc_port();

        proxy_pid = fork();
        if (proxy_pid == 0) {
            LOG(test) << "starting proxy, pid " << getpid();
            cerr << tc.edbdir << endl;
            setenv("EDBDIR", tc.edbdir.c_str(), 1);
            setenv("CRYPTDB_LOG", cryptdb_logger::getConf().c_str(), 1);
            setenv("CRYPTDB_USER", tc.user.c_str(), 1);
            setenv("CRYPTDB_PASS", tc.pass.c_str(), 1);
            setenv("CRYPTDB_DB", tc.db.c_str(), 1);
            if (type == PROXYSINGLE) {
                setenv("CRYPTDB_MODE", "single", 1);
            } else if (type == PROXYMULTI) {
                setenv("CRYPTDB_MODE", "multi", 1);
            } else {
                setenv("CRYPTDB_MODE", "plain", 1);
            }
            //setenv("CRYPTDB_PROXY_DEBUG","true",1);
            stringstream script_path, address, backend;
            script_path << "--proxy-lua-script=" << tc.edbdir << "/../mysqlproxy/wrapper.lua";
            address << "--proxy-address=" << tc.host << ":" << tc.port;
            backend << "--proxy-backend-addresses=" << tc.host << ":3306";
            cerr << "starting on port " << tc.port << "\n";
            execlp("mysql-proxy",
                   "mysql-proxy", "--plugins=proxy",
                                  "--event-threads=4",
                                  "--max-open-files=1024",
                                  script_path.str().c_str(),
                                  address.str().c_str(),
                                  backend.str().c_str(),
                                  (char *) 0);
            LOG(warn) << "could not execlp: " << strerror(errno);
            exit(-1);
        } else if (proxy_pid < 0) {
            LOG(warn) << "failed to fork";
            thrower() << "failed to fork: " << strerror(errno);
        } else {
            for (uint i = 0; i < 100; i++) {
                usleep(100000);
                LOG(test) << "checking if proxy is running yet..";
                if (try_connect_localhost(tc.port))
                    break;
            }

            for (uint64_t i = 0; i < no_conn; i++) {
                Connect * c = new Connect(tc.host, tc.user, tc.pass, tc.db, tc.port);
                conn_set.insert(c);
                if (type == PROXYMULTI) {
                    assert_s(c->execute("DROP FUNCTION IF EXISTS test"),"dropping function test for proxy-multi");
                    assert_s(c->execute("CREATE FUNCTION test (optionid integer) RETURNS bool RETURN optionid=20"),"creating function test for proxy-multi");
                }
            }
            this->conn = conn_set.begin();
        }
        break;
    default:
        assert_s(false, "invalid type passed to Connection");
    }
}    

void
Connection::stop() {
    switch (type) {
    case SINGLE:
    case MULTI:
        if (cl) {
            delete cl;
            cl = NULL;
        }
        break;
    case PROXYPLAIN:
    case PROXYSINGLE:
    case PROXYMULTI:
        if (proxy_pid > 0)
            kill(proxy_pid, SIGKILL);
    case UNENCRYPTED:
        for (auto c = conn_set.begin(); c != conn_set.end(); c++) {
            delete *c;
        }
        conn_set.clear();
        break;
    default:
        break;
    }
}

ResType
Connection::execute(string query) {
    switch (type) {
    case UNENCRYPTED:
    case PROXYPLAIN:
    case PROXYSINGLE:
    case PROXYMULTI:
        return executeConn(query);
    case SINGLE:
    case MULTI:
        return executeEDBProxy(query);
    default:
        assert_s(false, "unrecognized type in Connection");
    }
    return ResType(false);
}

void
Connection::executeFail(string query) {
    //cerr << type << " " << query << endl;
    LOG(test) << "Query: " << query << " could not execute" << endl;
}

ResType
Connection::executeEDBProxy(string query) {
    ResType res = cl->execute(query);
    if (!res.ok) {
        executeFail(query);
    }
    return res;
}
    
ResType
Connection::executeConn(string query) {
    DBResult * dbres = 0;
    auto ANON = cleanup([&dbres]() { if (dbres) delete dbres; });

    //cycle through connections of which should execute query
    conn++;
    if (conn == conn_set.end()) {
        conn = conn_set.begin();
    }
    if (!(*conn)->execute(query, dbres)) {
        executeFail(query);
        return ResType(false);
    }
    return dbres->unpack();
}

my_ulonglong
Connection::executeLast() {
    switch(type) {
    case SINGLE:
    case MULTI:
        return executeLastEDB();
    case UNENCRYPTED:
    case PROXYPLAIN:
    case PROXYSINGLE:
    case PROXYMULTI:
        return executeLastConn();
    default:
        assert_s(false, "type does not exist");
    }
    return 0;
}

my_ulonglong
Connection::executeLastConn() {
    conn++;
    if (conn == conn_set.end()) {
        conn = conn_set.begin();
    }
    return (*conn)->last_insert_id();
} 

my_ulonglong
Connection::executeLastEDB() {
    cerr << "No functionality for LAST_INSERT_ID() without proxy" << endl;
    return 0;
}

//----------------------------------------------------------------------

static void
CheckNULL(const TestConfig &tc, string test_query) {
    ntest++;

    //cerr << "CHECKING NULL" << endl;

    ResType test_res = test->execute(test_query);
    if (test_res.ok) {
        LOG(test) << "On query: " << test_query << "\nshould have returned false, but did not";
        if (tc.stop_if_fail) {
            assert_s(false, test_query + " should have return ok = false, but did not");
        }
        return;
    }

    npass++;
}

static void
CheckAnnotatedQuery(const TestConfig &tc, string control_query, string test_query)
{
    ntest++;

    ResType control_res;
    ResType test_res;

    LOG(test) << "control query: " << control_query;
    if (control_query == "") {
        control_res = ResType(true);
    } else {
        control_res = control->execute(control_query);
    }

    LOG(test) << "test query: " << test_query;
    if (test_query != "") {
        test_res = test->execute(test_query);
    } else {
        test_res = ResType(true);
    }

    if (control_res.ok != test_res.ok) {
        LOG(warn) << "control " << control_res.ok
                  << ", test " << test_res.ok
                  << " for query: " << test_query;

        if (tc.stop_if_fail)
            thrower() << "stop on failure";
    } else if (!match(test_res, control_res)) {
        LOG(warn) << "result mismatch for query: " << test_query;
        PrintRes(control_res);
        PrintRes(test_res);

        if (tc.stop_if_fail)
            thrower() << "stop on failure";
    } else {
        npass++;
    }
}

static void
CheckQuery(const TestConfig &tc, string query) {
    my_ulonglong test_res;
    my_ulonglong control_res;
    //TODO: should be case insensitive
    if (query == "SELECT LAST_INSERT_ID()") {
        ntest++;
        switch(test_type) {
        case UNENCRYPTED:
        case PROXYPLAIN:
        case PROXYSINGLE:
        case PROXYMULTI:
            if (control_type != SINGLE && control_type != MULTI) {
                test_res = test->executeLast();
                control_res = control->executeLast();
                if (test_res != control_res) {
                    if (tc.stop_if_fail) {
                        LOG(test) << "test last insert: " << test_res;
                        LOG(test) << "control last insert: " << control_res;
                        assert_s(false, "last insert id failed to match");
                    }
                    return;
                }
            }
            break;
        default:
            LOG(test) << "not a valid case of this test; skipped";
            break;
        }
        npass++;
        return;
    }
    CheckAnnotatedQuery(tc, query, query);
}

static void
CheckQueryList(const TestConfig &tc, const QueryList &queries) {
    for (unsigned int i = 0; i < queries.create.size(); i++) {
        string control_query = queries.create.choose(control_type)[i];
        string test_query = queries.create.choose(test_type)[i];
        CheckAnnotatedQuery(tc, control_query, test_query);
    }

    for (auto q = queries.common.begin(); q != queries.common.end(); q++) {
        switch (test_type) {
        case PLAIN:
        case SINGLE:
        case PROXYPLAIN:
        case PROXYSINGLE:
            CheckQuery(tc, q->query);
            break;

        case MULTI:
        case PROXYMULTI:
            if (q->test_res) {
                CheckNULL(tc, q->query);
            } else {
                CheckQuery(tc, q->query);
            }
            break;

        default:
            assert_s(false, "test_type invalid");
        }
    }

    for (unsigned int i = 0; i < queries.drop.size(); i++) {
        string control_query = queries.drop.choose(control_type)[i];
        string test_query = queries.drop.choose(test_type)[i];
        CheckAnnotatedQuery(tc, control_query, test_query);
    }
}

static void
RunTest(const TestConfig &tc) {
    CheckQueryList(tc, Insert);
    CheckQueryList(tc, Select);
    CheckQueryList(tc, Join);
    CheckQueryList(tc, Update);
    CheckQueryList(tc, Delete);
    CheckQueryList(tc, Search);
    CheckQueryList(tc, Basic);
    if (test_type == MULTI || test_type == PROXYMULTI) {
        test->restart();
    }
    if (control_type == MULTI || control_type == PROXYMULTI) {
        control->restart();
    }
    CheckQueryList(tc, PrivMessages);
    if (test_type == MULTI || test_type == PROXYMULTI) {
        test->restart();
    }
    if (control_type == MULTI || control_type == PROXYMULTI) {
        control->restart();
    }
    CheckQueryList(tc, UserGroupForum);
    if (test_type == MULTI || test_type == PROXYMULTI) {
        test->restart();
    }
    if (control_type == MULTI || control_type == PROXYMULTI) {
        control->restart();
    }
    CheckQueryList(tc, Auto);
    if (test_type == MULTI || test_type == PROXYMULTI) {
        test->restart();
    }
    if (control_type == MULTI || control_type == PROXYMULTI) {
        control->restart();
    }
    CheckQueryList(tc, Null);
    //everything has to restart so that last_insert_id() are lined up
    test->restart();
    control->restart();
    CheckQueryList(tc, ManyConnections);
}


//---------------------------------------------------------------------

TestQueries::TestQueries() {
}

TestQueries::~TestQueries() {
}

static test_mode
string_to_test_mode(const string &s)
{
    if (s == "plain")
        return UNENCRYPTED;
    else if (s == "single")
        return SINGLE;
    else if (s == "multi")
        return MULTI;
    else if (s == "proxy-plain")
        return PROXYPLAIN;
    else if (s == "proxy-single")
        return PROXYSINGLE;
    else if (s == "proxy-multi")
        return PROXYMULTI;
    else
        thrower() << "unknown test mode " << s;
}

void
TestQueries::run(const TestConfig &tc, int argc, char ** argv) {
    switch(argc) {
    case 4:
        //TODO check that argv[3] is a proper int-string
        no_conn = valFromStr(argv[3]);
    case 3:
        control_type = string_to_test_mode(argv[1]);
        test_type = string_to_test_mode(argv[2]);
        break;
    default:
        cerr << "Usage:" << endl
             << "    .../tests/test queries control-type test-type [num_conn]" << endl
             << "Possible control and test types:" << endl
             << "    plain" << endl
             << "    single" << endl
             << "    multi" << endl
             << "    proxy-plain" << endl
             << "    proxy-single" << endl
             << "    proxy-multi" << endl
             << "single and multi make connections through EDBProxy" << endl
             << "proxy-* makes connections *'s encryption type through the proxy" << endl
             << "num_conn is the number of conns made to a single db (default 1)" << endl
             << "    for num_conn > 1, control and test should both be proxy-* for valid results" << endl;
        return;
    }        

    if (no_conn > 1) {
        switch(test_type) {
        case UNENCRYPTED:
        case SINGLE:
        case MULTI:
            if (control_type == PROXYPLAIN ||
                control_type == PROXYSINGLE || control_type == PROXYMULTI)
            {
                cerr << "cannot compare proxy-* vs non-proxy-* when there are multiple connections" << endl;
                return;
            }
            break;
        case PROXYPLAIN:
        case PROXYSINGLE:
        case PROXYMULTI:
            if (control_type == UNENCRYPTED || control_type == SINGLE ||
                control_type == MULTI)
            {
                cerr << "cannot compare proxy-* vs non-proxy-* when there are multiple connections" << endl;
                return;
            }
            break;
        default:
            cerr << "test_type does not exist" << endl;
        }
    }


    TestConfig control_tc = TestConfig();
    control_tc.db = control_tc.db+"_control";
    
    Connection control_(control_tc, control_type);
    control = &control_;

    Connection test_(tc, test_type);
    test = &test_;

    enum { nrounds = 1 };
    for (uint i = 0; i < nrounds; i++)
        RunTest(tc);

    cerr << "RESULT: " << npass << "/" << ntest << endl;
}

