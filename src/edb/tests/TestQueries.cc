/*
 * TestQueries.cc
 *  -- end to end query and result test, independant of connection process
 *
 *
 */

#include <netinet/in.h>
#include "TestQueries.h"
#include "cryptdb_log.h"

static int ntest = 0;
static int npass = 0;
static int control_type;
static int test_type;
static int no_conn = 1;
static Connection * control;
static Connection * test;

static QueryList Insert = QueryList("SingleInsert",
                                    {"CREATE TABLE test_insert (id integer primary key auto_increment, age integer, salary integer, address text, name text)"},
                                    {"CREATE TABLE test_insert (id integer primary key auto_increment, age enc integer, salary enc integer, address enc text, name text)"},
                                    {"CREATE TABLE test_insert (id integer primary key auto_increment, age integer, salary integer, address text, name text)"},
                                    {Query("INSERT INTO test_insert VALUES (1, 21, 100, '24 Rosedale, Toronto, ONT', 'Pat Carlson')", false),
                                            Query("SELECT * FROM test_insert",false),
                                            Query("INSERT INTO test_insert (id, age, salary, address, name) VALUES (2, 23, 101, '25 Rosedale, Toronto, ONT', 'Pat Carlson2')",false),
                                            Query("SELECT * FROM test_insert",false),
                                            Query("INSERT INTO test_insert (age, address, salary, name, id) VALUES (25, '26 Rosedale, Toronto, ONT', 102, 'Pat2 Carlson', 3)",false),
                                            Query("SELECT * FROM test_insert",false),
                                            Query("INSERT INTO test_insert (age, address, salary, name) VALUES (26, 'test address', 30, 'test name')",false),
                                            Query("SELECT * FROM test_insert",false),
                                            Query("INSERT INTO test_insert (age, address, salary, name) VALUES (27, 'test address2', 31, 'test name')",false),
                                            Query("select last_insert_id()",false),
                                            Query("INSERT INTO test_insert (id) VALUES (7)",false),
                                            Query("select sum(id) from test_insert",false),
                                            Query("INSERT INTO test_insert (age) VALUES (40)",false),
                                            //TODO: proxy has issues with this one...?
                                            //Query("SELECT age FROM test_insert",false),
                                            Query("INSERT INTO test_insert (name) VALUES ('Wendy')",false),
                                            Query("SELECT name FROM test_insert WHERE id=10",false),
                                            Query("INSERT INTO test_insert (name, address, id, age) VALUES ('Peter Pan', 'first star to the right and straight on till morning', 42, 10)",false),
                                            Query("SELECT name, address, age FROM test_insert WHERE id=42",false)},
                                    {"DROP TABLE test_insert"},
                                    {"DROP TABLE test_insert"},
                                    {"DROP TABLE test_insert"});

//migrated from TestSinglePrinc TestSelect
static QueryList Select = QueryList("SingleSelect",
                                    {"CREATE TABLE test_select (id integer, age integer, salary integer, address text, name text)"},
                                    {"CREATE TABLE test_select (id integer, age enc integer, salary enc integer, address enc text, name text)"},
                                    {"CREATE TABLE test_select (id integer, age integer, salary integer, address text, name text)"},
                                    {Query("INSERT INTO test_select VALUES (1, 10, 0, 'first star to the right and straight on till morning', 'Peter Pan')",false),
                                            Query("INSERT INTO test_select VALUES (2, 16, 1000, 'Green Gables', 'Anne Shirley')",false),
                                            Query("INSERT INTO test_select VALUES (3, 8, 0, 'London', 'Lucy')",false),
                                            Query("INSERT INTO test_select VALUES (4, 10, 0, 'London', 'Edmund')",false),
                                            Query("INSERT INTO test_select VALUES (5, 30, 100000, '221B Baker Street', 'Sherlock Holmes')",false),
                                            Query("SELECT * FROM test_select",false),
                                            Query("SELECT max(id) FROM test_select",false),
                                            Query("SELECT max(salary) FROM test_select",false),
                                            Query("SELECT COUNT(*) FROM test_select",false),
                                            Query("SELECT COUNT(DISTINCT age) FROM test_select",false),
                                            Query("SELECT COUNT(DISTINCT(address)) FROM test_select",false),
                                            Query("SELECT name FROM test_select",false),
                                            Query("SELECT address FROM test_select",false),
                                            Query("SELECT * FROM test_select WHERE id>3",false),
                                            Query("SELECT * FROM test_select WHERE age = 8",false),
                                            Query("SELECT * FROM test_select WHERE salary=15",false),
                                            Query("SELECT * FROM test_select WHERE age > 10",false),
                                            Query("SELECT * FROM test_select WHERE age = 10 AND salary = 0",false),
                                            Query("SELECT * FROM test_select WHERE age = 10 OR salary = 0",false),
                                            Query("SELECT * FROM test_select WHERE name = 'Peter Pan'",false),
                                            Query("SELECT * FROM test_select WHERE address='Green Gables'",false),
                                            Query("SELECT * FROM test_select WHERE address <= '221C'",false),
                                            Query("SELECT * FROM test_select WHERE address >= 'Green Gables' AND age > 9",false),
                                            Query("SELECT * FROM test_select WHERE address >= 'Green Gables' OR age > 9",false),
                                            Query("SELECT * FROM test_select ORDER BY id",false),
                                            Query("SELECT * FROM test_select ORDER BY salary",false),
                                            Query("SELECT * FROM test_select ORDER BY name",false),
                                            Query("SELECT * FROM test_select ORDER BY address",false),
                                            Query("SELECT sum(age) FROM test_select GROUP BY address",false),
                                            Query("SELECT salary, max(id) FROM test_select GROUP BY salary",false),
                                            Query("SELECT * FROM test_select GROUP BY age ORDER BY age",false),
                                            Query("SELECT * FROM test_select ORDER BY age ASC",false),
                                            Query("SELECT * FROM test_select ORDER BY address DESC",false),
                                            Query("SELECT sum(age) as z FROM test_select",false),
                                            Query("SELECT sum(age) z FROM test_select",false),
                                            Query("SELECT min(t.id) a FROM test_select AS t",false),
                                            Query("SELECT t.address AS b FROM test_select t",false)},
                                    {"DROP TABLE test_select"},
                                    {"DROP TABLE test_select"},
                                    {"DROP TABLE test_select"});

//migrated from TestSinglePrinc TestJoin
static QueryList Join = QueryList("SingleJoin",
                                  {"CREATE TABLE test_join1 (id integer, age integer, salary integer, address text, name text)",
                                   "CREATE TABLE test_join2 (id integer, books integer, name text)"},
                                  {"CREATE TABLE test_join1 (id integer, age enc integer, salary enc integer, address enc text, name text)",
                                   "CREATE TABLE test_join2 (id integer, books enc integer, name enc text)"},
                                  {"CREATE TABLE test_join1 (id integer, age integer, salary integer, address text, name text)",
                                   "CREATE TABLE test_join2 (id integer, books integer, name text)"},
                                  {Query("INSERT INTO test_join1 VALUES (1, 10, 0, 'first star to the right and straight on till morning','Peter Pan')",false),
                                          Query("INSERT INTO test_join1 VALUES (2, 16, 1000, 'Green Gables', 'Anne Shirley')",false),
                                          Query("INSERT INTO test_join1 VALUES (3, 8, 0, 'London', 'Lucy')",false),
                                          Query("INSERT INTO test_join1 VALUES (4, 10, 0, 'London', 'Edmund')",false),
                                          Query("INSERT INTO test_join1 VALUES (5, 30, 100000, '221B Baker Street', 'Sherlock Holmes')",false),
                                          Query("INSERT INTO test_join2 VALUES (1, 6, 'Peter Pan')",false),
                                          Query("INSERT INTO test_join2 VALUES (2, 8, 'Anne Shirley')",false),
                                          Query("INSERT INTO test_join2 VALUES (3, 7, 'Lucy')",false),
                                          Query("INSERT INTO test_join2 VALUES (4, 7, 'Edmund')",false),
                                          Query("INSERT INTO test_join2 VALUES (10, 4, '221B Baker Street')",false),
                                          Query("SELECT address FROM test_join1, test_join2 WHERE test_join1.id=test_join2.id",false),
                                          Query("SELECT test_join1.id, test_join2.id, age, books, test_join2.name FROM test_join1, test_join2 WHERE test_join1.id = test_join2.id",false),
                                          Query("SELECT test_join1.name, age, salary, test_join2.name, books FROM test_join1, test_join2 WHERE test_join1.age=test_join2.books",false),
                                          //we don't support things that join unecrypted columns to encrypted columns
                                          //Query("SELECT * FROM test_join1, test_join2 WHERE test_join1.name=test_join2.name",false),
                                          Query("SELECT * FROM test_join1, test_join2 WHERE test_join1.address=test_join2.name",false),
                                          Query("SELECT address FROM test_join1 AS a, test_join2 WHERE a.id=test_join2.id",false),
                                          Query("SELECT a.id, b.id, age, books, b.name FROM test_join1 a, test_join2 AS b WHERE a.id=b.id",false),
                                          Query("SELECT test_join1.name, age, salary, b.name, books FROM test_join1, test_join2 b WHERE test_join1.age = b.books",false)},
                                  {"DROP TABLE test_join1",
                                   "DROP TABLE test_join2"},
                                  {"DROP TABLE test_join1",
                                   "DROP TABLE test_join2"},
                                  {"DROP TABLE test_join1",
                                   "DROP TABLE test_join2"});

//migrated from TestSinglePrinc TestUpdate
static QueryList Update = QueryList("SingleUpdate",
                                    {"CREATE TABLE test_update (id integer, age integer, salary integer, address text, name text)"},
                                    {"CREATE TABLE test_update (id integer, age enc integer, salary enc integer, address enc text, name enc text)"},
                                    {"CREATE TABLE test_update (id integer, age integer, salary integer, address text, name text)"},
                                    {Query("INSERT INTO test_update VALUES (1, 10, 0, 'first star to the right and straight on till morning','Peter Pan')",false),
                                            Query("INSERT INTO test_update VALUES (2, 16, 1000, 'Green Gables', 'Anne Shirley')",false),
                                            Query("INSERT INTO test_update VALUES (3, 8, 0, 'London', 'Lucy')",false),
                                            Query("INSERT INTO test_update VALUES (4, 10, 0, 'London', 'Edmund')",false),
                                            Query("INSERT INTO test_update VALUES (5, 30, 100000, '221B Baker Street', 'Sherlock Holmes')",false),
                                            Query("INSERT INTO test_update VALUES (6, 11, 0 , 'hi', 'no one')",false),
                                            Query("UPDATE test_update SET salary=0",false),
                                            Query("SELECT * FROM test_update",false),
                                            Query("UPDATE test_update SET age=21 WHERE id = 6",false),
                                            Query("SELECT * FROM test_update",false),
                                            Query("UPDATE test_update SET address='Pemberly', name='Elizabeth Darcy' WHERE id=6",false),
                                            Query("SELECT * FROM test_update",false),
                                            Query("UPDATE test_update SET salary=55000 WHERE age=30",false),
                                            Query("SELECT * FROM test_update",false),
                                            Query("UPDATE test_update SET salary=20000 WHERE address='Pemberly'",false),
                                            Query("SELECT * FROM test_update",false),
                                            Query("SELECT age FROM test_update WHERE age > 20",false),
                                            Query("SELECT id FROM test_update",false),
                                            Query("SELECT sum(age) FROM test_update",false),
                                            Query("UPDATE test_update SET age=20 WHERE name='Elizabeth Darcy'",false),
                                            Query("SELECT * FROM test_update WHERE age > 20",false),
                                            Query("SELECT sum(age) FROM test_update",false),
                                            Query("UPDATE test_update SET age = age + 2",false),
                                            Query("SELECT age FROM test_update",false),
                                            Query("UPDATE test_update SET id = id + 10, salary = salary + 19, name = 'xxx', address = 'foo' WHERE address = 'London'",false),
                                            Query("SELECT * FROM test_update",false),
                                            Query("SELECT * FROM test_update WHERE address < 'fml'",false),
                                            Query("UPDATE test_update SET address = 'Neverland' WHERE id=1",false),
                                            Query("SELECT * FROM test_update",false)},
                                    {"DROP TABLE test_update"},
                                    {"DROP TABLE test_update"},
                                    {"DROP TABLE test_update"});


//migrated from TestDelete
static QueryList Delete = QueryList("SingleDelete",
                                    {"CREATE TABLE test_delete (id integer, age integer, salary integer, address text, name text)"},
                                    {"CREATE TABLE test_delete (id integer, age enc integer, salary enc integer, address enc text, name enc text)"},
                                    {"CREATE TABLE test_delete (id integer, age integer, salary integer, address text, name text)"},
                                    {Query("INSERT INTO test_delete VALUES (1, 10, 0, 'first star to the right and straight on till morning','Peter Pan')",false),
                                            Query("INSERT INTO test_delete VALUES (2, 16, 1000, 'Green Gables', 'Anne Shirley')",false),
                                            Query("INSERT INTO test_delete VALUES (3, 8, 0, 'London', 'Lucy')",false),
                                            Query("INSERT INTO test_delete VALUES (4, 10, 0, 'London', 'Edmund')",false),
                                            Query("INSERT INTO test_delete VALUES (5, 30, 100000, '221B Baker Street', 'Sherlock Holmes')",false),
                                            Query("INSERT INTO test_delete VALUES (6, 21, 2000, 'Pemberly', 'Elizabeth')",false),
                                            Query("INSERT INTO test_delete VALUES (7, 10000, 1, 'Mordor', 'Sauron')",false),
                                            Query("INSERT INTO test_delete VALUES (8, 25, 100, 'The Heath', 'Eustacia Vye')",false),
                                            Query("DELETE FROM test_delete WHERE id=1",false),
                                            Query("SELECT * FROM test_delete",false),
                                            Query("DELETE FROM test_delete WHERE age=30",false),
                                            Query("SELECT * FROM test_delete",false),
                                            Query("DELETE FROM test_delete WHERE name='Eustacia Vye'",false),
                                            Query("SELECT * FROM test_delete",false),
                                            Query("DELETE FROM test_delete WHERE address='London'",false),
                                            Query("SELECT * FROM test_delete",false),
                                            Query("DELETE FROM test_delete WHERE salary = 1",false),
                                            Query("SELECT * FROM test_delete",false),
                                            Query("INSERT INTO test_delete VALUES (1, 10, 0, 'first star to the right and straight on till morning','Peter Pan')",false),
                                            Query("SELECT * FROM test_delete",false),
                                            Query("DELETE FROM test_delete",false),
                                            Query("SELECT * FROM test_delete",false)},
                                    {"DROP TABLE test_delete"},
                                    {"DROP TABLE test_delete"},
                                    {"DROP TABLE test_delete"});

//migrated from TestSearch
static QueryList Search = QueryList("SingleSearch",
                                    {"CREATE TABLE test_search (id integer, searchable text)"},
                                    {"CREATE TABLE test_search (id integer, searchable enc search text)"},
                                    {"CREATE TABLE test_search (id integer, searchable text)"},
                                    {Query("INSERT INTO test_search VALUES (1, 'short text')",false),
                                            Query("INSERT INTO test_search VALUES (2, 'Text with CAPITALIZATION')",false),
                                            Query("INSERT INTO test_search VALUES (3, '')",false),
                                            Query("INSERT INTO test_search VALUES (4, 'When I have fears that I may cease to be, before my pen has gleaned my teeming brain; before high piled books in charactery hold like ruch garners the full-ripened grain. When I behold on the nights starred face huge cloudy symbols of high romance and think that I may never live to trace their shadows with the magic hand of chance; when I feel fair creature of the hour that I shall never look upon thee more, never have relish of the faerie power of unreflecting love, I stand alone on the edge of the wide world and think till love and fame to nothingness do sink')",false),
                                            Query("SELECT * FROM test_search WHERE searchable LIKE '%text%'",false),
                                            Query("SELECT * FROM test_search WHERE searchable LIKE 'short%'",false),
                                            Query("SELECT * FROM test_search WHERE searchable LIKE ''",false),
                                            Query("SELECT * FROM test_search WHERE searchable LIKE '%capitalization'",false),
                                            Query("SELECT * FROM test_search WHERE searchable LIKE 'noword'",false),
                                            Query("SELECT * FROM test_search WHERE searchable LIKE 'when%'",false),
                                            Query("SELECT * FROM test_search WHERE searchable < 'slow'",false),
                                            Query("UPDATE test_search SET searchable='text that is new' WHERE id=1",false),
                                            Query("SELECT * FROM test_search WHERE searchable < 'slow'",false)},
                                    {"DROP TABLE test_search"},
                                    {"DROP TABLE test_search"},
                                    {"DROP TABLE test_search"});

//migrated from TestMultiPrinc BasicFunctionality
static QueryList Basic = QueryList("MultiBasic",
                                   {"CREATE TABLE t1 (id integer, post text, age bigint)",
                                           "CREATE TABLE u_basic (id integer, username text)",
                                           "CREATE TABLE "+PWD_TABLE_PREFIX+"u_basic (username text, psswd text)"},
                                   {"CREATE TABLE t1 (id integer, post text, age bigint)",
                                           "CREATE TABLE u_basic (id integer, username text)",
                                           "CREATE TABLE "+PWD_TABLE_PREFIX+"u_basic (username text, psswd text)"},
                                   {"CREATE TABLE t1 (id integer, post encfor id det text, age encfor id ope bigint)",
                                           "CREATE TABLE u_basic (id equals t1.id integer, username givespsswd id text)",
                                           "COMMIT ANNOTATIONS"},
                                   {Query("INSERT INTO "+PWD_TABLE_PREFIX+"u_basic (username, psswd) VALUES ('alice', 'secretalice')",false),
                                           Query("DELETE FROM "+PWD_TABLE_PREFIX+"u_basic WHERE username='alice'",false),
                                           Query("INSERT INTO "+PWD_TABLE_PREFIX+"u_basic (username, psswd) VALUES ('alice', 'secretalice')",false),
                                           Query("INSERT INTO u_basic VALUES (1, 'alice')",false),
                                           Query("SELECT * FROM u_basic",false),
                                           Query("INSERT INTO t1 VALUES (1, 'text which is inserted', 23)",false),
                                           Query("SELECT * FROM t1",false),
                                           Query("SELECT post from t1 WHERE id = 1 AND age = 23",false),
                                           Query("UPDATE t1 SET post='hello!' WHERE age > 22 AND id =1",false),
                                           Query("SELECT * FROM t1",false),
                                           Query("INSERT INTO "+PWD_TABLE_PREFIX+"u_basic (username, psswd) VALUES ('raluca','secretraluca')",false),
                                           Query("INSERT INTO u_basic VALUES (2, 'raluca')",false),
                                           Query("SELECT * FROM u_basic",false),
                                           Query("INSERT INTO t1 VALUES (2, 'raluca has text here', 5)",false),
                                           Query("SELECT * FROM t1",false) },
                                   {"DROP TABLE u_basic",
                                           "DROP TABLE t1",
                                           "DROP TABLE "+PWD_TABLE_PREFIX+"u_basic"},
                                   {"DROP TABLE u_basic",
                                           "DROP TABLE t1",
                                           "DROP TABLE "+PWD_TABLE_PREFIX+"u_basic"},
                                   {"DROP TABLE u_basic",
                                           "DROP TABLE t1",
                                           "DROP TABLE nop"} );

//migrated from PrivMessages
static QueryList PrivMessages = QueryList("MultiPrivMessages",
                                          {"CREATE TABLE msgs (msgid integer, msgtext text)",
                                                  "CREATE TABLE privmsg (msgid integer, recid integer, senderid integer)",
                                                  "CREATE TABLE u_mess (userid integer, username text)",
                                                  "CREATE TABLE "+PWD_TABLE_PREFIX+"u_mess (username text, psswd text)"},
                                          {"CREATE TABLE msgs (msgid integer, msgtext text)",
                                                  "CREATE TABLE privmsg (msgid integer, recid integer, senderid integer)",
                                                  "CREATE TABLE u_mess (userid integer, username text)",
                                                  "CREATE TABLE "+PWD_TABLE_PREFIX+"u_mess (username text, psswd text)"},
                                          {"CREATE TABLE msgs (msgid equals privmsg.msgid integer, msgtext encfor msgid text)",
                                                  "CREATE TABLE privmsg (msgid integer, recid equals u_mess.userid hasaccessto msgid integer, senderid hasaccessto msgid integer)",
                                                  "CREATE TABLE u_mess (userid equals privmsg.senderid integer, username givespsswd userid text)",
                                                  "COMMIT ANNOTATIONS"},
                                          {Query("INSERT INTO "+PWD_TABLE_PREFIX+"u_mess (username, psswd) VALUES ('alice', 'secretalice')",false),
                                                  Query("INSERT INTO "+PWD_TABLE_PREFIX+"u_mess (username, psswd) VALUES ('bob', 'secretbob')",false),
                                                  Query("INSERT INTO u_mess VALUES (1, 'alice')",false),
                                                  Query("INSERT INTO u_mess VALUES (1, 'bob')",false),
                                                  Query("INSERT INTO privmsg (msgid, recid, senderid) VALUES (9, 1, 2)",false),
                                                  Query("INSERT INTO msgs VALUES (1, 'hello world')",false),
                                                  Query("SELECT msgtext FROM msgs WHERE msgid=1",false),
                                                  Query("SELECT msgtext FROM msgs, privmsg, u_mess WHERE username = 'alice' AND userid = recid AND msgs.msgid = privmsg.msgid",false),
                                                  Query("INSERT INTO msgs VALUES (9, 'message for alice from bob')",false),
                                                  Query("SELECT msgtext FROM msgs, privmsg, u_mess WHERE username = 'alice' AND userid = recid AND msgs.msgid = privmsg.msgid",false)},
                                          {"DROP TABLE msgs",
                                                  "DROP TABLE privmsg",
                                                  "DROP TABLE u_mess",
                                                  "DROP TABLE "+PWD_TABLE_PREFIX+"u_mess"},
                                          {"DROP TABLE msgs",
                                                  "DROP TABLE privmsg",
                                                  "DROP TABLE u_mess",
                                                  "DROP TABLE "+PWD_TABLE_PREFIX+"u_mess"},
                                          {"DROP TABLE msgs",
                                                  "DROP TABLE privmsg",
                                                  "DROP TABLE u_mess",
                                                  "DROP TABLE nop"} );

//migrated from UserGroupForum
static QueryList UserGroupForum = QueryList("UserGroupForum",
                                            {"CREATE TABLE u (userid integer, username text)",
                                                    "CREATE TABLE usergroup (userid integer, groupid integer)",
                                                    "CREATE TABLE groupforum (forumid integer, groupid integer, optionid integer)",
                                                    "CREATE TABLE forum (forumid integer, forumtext text)",
                                                    "CREATE TABLE "+PWD_TABLE_PREFIX+"u (username text, psswd text)"},
                                            {"CREATE TABLE u (userid integer, username text)",
                                                    "CREATE TABLE usergroup (userid integer, groupid integer)",
                                                    "CREATE TABLE groupforum (forumid integer, groupid integer, optionid integer)",
                                                    "CREATE TABLE forum (forumid integer, forumtext text)",
                                                    "CREATE TABLE "+PWD_TABLE_PREFIX+"u (username text, psswd text)"},
                                            {"CREATE TABLE u (userid integer, username givespsswd userid text)",
                                                    "CREATE TABLE usergroup (userid equals u.userid hasaccessto groupid integer, groupid integer)",
                                                    "CREATE TABLE groupforum (forumid equals forum.forumid integer, groupid equals usergroup.groupid hasaccessto forumid integer, optionid integer)",
                                                    "CREATE TABLE forum (forumid integer, forumtext encfor forumid text)",
                                                    "COMMIT ANNOTATIONS"},
                                            {Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('alice', 'secretalice')",false),
                                                    Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('bob', 'secretbob')",false),
                                                    Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('chris', 'secretchris')",false),
                                                    Query("INSERT INTO u VALUES (1, 'alice')",false),
                                                    Query("INSERT INTO u VALUES (2, 'bob')",false),
                                                    Query("INSERT INTO u VALUES (3, 'chris')",false),
                                                    Query("INSERT INTO usergroup VALUES (1,1)",false),
                                                    Query("INSERT INTO usergroup VALUES (2,2)",false),
                                                    Query("INSERT INTO usergroup VALUES (3,1)",false),
                                                    Query("INSERT INTO usergroup VALUES (3,2)",false),
                                                    Query("SELECT * FROM usergroup",false),
                                                    Query("INSERT INTO groupforum VALUES (1,1,14)",false),
                                                    Query("INSERT INTO groupforum VALUES (1,1,20)",false),
                                                    Query("SELECT * FROM groupforum",false),
                                                    Query("INSERT INTO forum VALUES (1, 'sucess-- you can see forum text')",false),
                                                    Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='alice'",false),
                                                    Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='bob'",false),
                                                    Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='chris'",false),
                                                    //alice
                                                    Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('alice', 'secretalice')",false),
                                                    Query("SELECT forumtext FROM forum WHERE forumid=1",false),
                                                    Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='alice'",false),
                                                    //bob
                                                    Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('bob', 'secretbob')",false),
                                                    Query("SELECT forumtext FROM forum WHERE forumid=1",true),
                                                    Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='bob'",false),
                                                    //chris
                                                    Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('chris', 'secretchris')",false),
                                                    Query("SELECT forumtext FROM forum WHERE forumid=1",false),
                                                    Query("UPDATE forum SET forumtext='you win!' WHERE forumid=1",false),
                                                    Query("SELECT forumtext FROM forum WHERE forumid=1",false),
                                                    Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='chris'",false),
                                                    //alice
                                                    Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('alice','secretalice')",false),
                                                    Query("SELECT forumtext FROM forum WHERE forumid=1",false),
                                                    Query("INSERT INTO forum VALUES (2, 'orphaned text! everyone should be able to see me')",false),
                                                    Query("SELECT forumtext FROM forum WHERE forumid=2",false),
                                                    Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='alice'",false),
                                                    //bob
                                                    Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('bob', 'secretbob')",false),
                                                    Query("SELECT forumtext FROM forum WHERE forumid=2",false),
                                                    Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='bob'",false),
                                                    //chris
                                                    Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('chris','secretchris')",false),
                                                    Query("SELECT forumtext FROM forum WHERE forumid=2",false),
                                                    Query("INSERT INTO groupforum VALUES (2,2,20)",false),
                                                    Query("SELECT forumtext FROM forum AS f, groupforum AS g, usergroup AS ug, u WHERE f.forumid=g.forumid AND g.groupid=ug.groupid AND ug.userid=u.userid AND u.username='chris' AND g.optionid=20",false),
                                                    Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='chris'",false),
                                                    //bob
                                                    Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('bob','secretbob')",false),
                                                    Query("SELECT forumtext FROM forum AS f, groupforum AS g, usergroup AS ug, u WHERE f.forumid=g.forumid AND g.groupid=ug.groupid AND ug.userid=u.userid AND u.username='bob' AND g.optionid=20",false),
                                                    Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='bob'",false),
                                                    //alice
                                                    Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('alice','secretalice')",false),


                                                    Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='alice'",false),






                                                    Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('chris','secretchris')",false),
                                                    Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='chris'",false),
                                                    Query("INSERT INTO "+PWD_TABLE_PREFIX+"u (username, psswd) VALUES ('chris','secretchris')",false),
                                                    Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='chris'",false),




                                            {"DROP TABLE u",
                                                    "DROP TABLE usergroup",
                                                    "DROP TABLE groupforum",
                                                    "DROP TABLE forum",
                                                    "DROP TABLE "+PWD_TABLE_PREFIX+"u"},
                                            {"DROP TABLE u",
                                                    "DROP TABLE usergroup",
                                                    "DROP TABLE groupforum",
                                                    "DROP TABLE forum",
                                                    "DROP TABLE "+PWD_TABLE_PREFIX+"u"},
                                            {"DROP TABLE u",
                                                    "DROP TABLE usergroup",
                                                    "DROP TABLE groupforum",
                                                    "DROP TABLE forum",
                                                    "DROP TABLE nop"} );

Connection::Connection(const TestConfig &input_tc, int input_type) {
    if (input_type > 3) { 
        this->type = 3;
    } else {
        this->type = input_type;
    }
    this->tc = input_tc;
    start();
}


Connection::~Connection() {
    stop();
}

void
Connection::restart() {
    stop();
    start();
}

void
Connection::start() {
    uint64_t mkey = 1133421234;
    string masterKey = BytesFromInt(mkey, AES_KEY_BYTES); 
    switch (type) {
        //plain -- new connection straight to the DB
    case 0:
        conn = new Connect(tc.host, tc.user, tc.pass, tc.db, tc.port);
        break;
        //single -- new EDBClient
    case 1:
        cl = new EDBClient(tc.host, tc.user, tc.pass, tc.db, tc.port, false);
        cl->setMasterKey(masterKey);
        break;
        //multi -- new EDBClient
    case 2:
        cl = new EDBClient(tc.host, tc.user, tc.pass, tc.db, tc.port, true);
        cl->setMasterKey(masterKey);
        cl->plain_execute("DROP FUNCTION IF EXISTS test");
        cl->plain_execute("CREATE FUNCTION test (optionid integer) RETURNS bool RETURN optionid=20");
        cl->execute("CREATE TABLE nop (nothing integer)");
        break;
        //proxy -- start proxy in separate process and initialize connection
    case 3:
        this->tc.port = 5123;
        proxy_pid = fork();
        if (proxy_pid == 0) {
            LOG(test) << "starting proxy, pid " << getpid();
            setenv("EDBDIR", tc.edbdir.c_str(), 1);
            setenv("CRYPTDB_USER", tc.user.c_str(), 1);
            setenv("CRYPTDB_PASS", tc.pass.c_str(), 1);
            setenv("CRYPTDB_DB", tc.db.c_str(), 1);
            string script_path = "--proxy-lua-script=" + tc.edbdir
                                                       + "/../mysqlproxy/wrapper.lua";
            execlp("mysql-proxy",
                   "mysql-proxy", "--plugins=proxy",
                                  "--max-open-files=1024",
                                  script_path.c_str(),
                                  "--proxy-address=localhost:5123",
                                  "--proxy-backend-addresses=localhost:3306",
                                  (char *) 0);
            LOG(warn) << "could not execlp: " << strerror(errno);
            exit(-1);
        } else if (proxy_pid < 0) {
            cerr << "failed to fork" << endl;
            exit(1);
        } else {
            for (uint i = 0; i < 100; i++) {
                usleep(100000);
                LOG(test) << "checking if proxy is running yet..";

                int fd = socket(AF_INET, SOCK_STREAM, 0);
                assert(fd >= 0);

                struct sockaddr_in sin;
                sin.sin_family = AF_INET;
                sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                sin.sin_port = htons(tc.port);
                int r = connect(fd, (struct sockaddr *) &sin, sizeof(sin));
                LOG(test) << "connect: " << r;
                close(fd);

                if (r == 0)
                    break;
            }

            conn = new Connect(tc.host, tc.user, tc.pass, tc.db, tc.port);
        }
        break;
    default:
        assert_s(false, "invalid type passed to Connection");
    }
}    

void
Connection::stop() {
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
    cerr << type << " " << query << endl;
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
CheckNULL(const TestConfig &tc, string test_query) {
    ntest++;

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
CheckAnnotatedQuery(const TestConfig &tc, string control_query, string test_query) {
    ntest++;

    ResType control_res = control->execute(control_query);
    ResType test_res = test->execute(test_query);
    if (control_res.ok != test_res.ok) {
        LOG(test) << "Query: " << test_query << "\ncould not execute in test or in control";
        if (tc.stop_if_fail) {
            assert_s(false, test_query+" did not execute properly");
        }
        return;
    }
    if (!match(test_res, control_res)) {
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
    CheckAnnotatedQuery(tc, query, query);
}

static void
CheckQueryList(const TestConfig &tc, const QueryList &queries) {
    assert_s(queries.plain_create.size() == queries.single_create.size() && queries.plain_create.size() == queries.multi_create.size(), "create query lists are not the same size");
    assert_s(queries.plain_drop.size() == queries.single_drop.size() && queries.plain_drop.size() == queries.multi_drop.size(), "drop query lists are not the same size");

    for (unsigned int i = 0; i < queries.plain_create.size(); i++) {
        string control_query;
        string test_query;
        switch(control_type) {
        case 0:
        case 3:
            control_query = queries.plain_create[i];
            break;
        case 1:
        case 4:
            control_query = queries.single_create[i];
            break;
        case 2:
        case 5:
            control_query = queries.multi_create[i];
            break;
        default:
            assert_s(false, "control_type invalid");
        }
        switch(test_type) {
        case 0:
        case 3:
            test_query = queries.plain_create[i];
            break;
        case 1:
        case 4:
            test_query = queries.single_create[i];
            break;
        case 2:
        case 5:
            test_query = queries.multi_create[i];
            break;
        default:
            assert_s(false, "test_type invalid");
        }
        CheckAnnotatedQuery(tc, control_query, test_query);
    }

    for (auto q = queries.common.begin(); q != queries.common.end(); q++) {
        switch (test_type) {
        case 0:
        case 1:
        case 3:
        case 4:
            CheckQuery(tc, q->query);
            break;
        case 2:
        case 5:
            if (q->multi_null) {
                CheckNULL(tc, q->query);
            } else {
                CheckQuery(tc, q->query);
            }
            break;
        default:
            assert_s(false, "test_type invalid");
        }
    }

    for (unsigned int i = 0; i < queries.plain_drop.size(); i++) {
        string control_query;
        string test_query;
        switch(control_type) {
        case 0:
        case 3:
            control_query = queries.plain_drop[i];
            break;
        case 1:
        case 4:
            control_query = queries.single_drop[i];
            break;
        case 2:
        case 5:
            control_query = queries.multi_drop[i];
            break;
        default:
            assert_s(false, "control_type invalid");
        }
        switch(test_type) {
        case 0:
        case 3:
            test_query = queries.plain_drop[i];
            break;
        case 1:
        case 4:
            test_query = queries.single_drop[i];
            break;
        case 2:
        case 5:
            test_query = queries.multi_drop[i];
            break;
        default:
            assert_s(false, "test_type invalid");
        }
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
    if (test_type == 2 || test_type == 5) {
        test->restart();
    }
    if (control_type == 2 || control_type == 5) {
        control->restart();
    }
    CheckQueryList(tc, PrivMessages);
    if (test_type == 2 || test_type == 5) {
        test->restart();
    }
    if (control_type == 2 || control_type == 5) {
        control->restart();
    }
    CheckQueryList(tc, UserGroupForum);

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
            //create file that specifies single or multi (system/fopen)
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
        cerr << "Usage:" << endl
             << "    .../tests/test queries control-type test-type [num_conn]" << endl
             << "Possible control and test types:" << endl
             << "    plain" << endl
             << "    single" << endl
             << "    multi" << endl
             << "    proxy-plain" << endl
             << "    proxy-single" << endl
             << "    proxy-multi" << endl
             << "single and multi make connections through EDBClient" << endl
             << "proxy-* makes connections *'s encryption type through the proxy" << endl
             << "num_conn is the number of conns made to a single db (default 1)" << endl;
        return;
    }        

    //query: do they need their own tc? yes!  different dbs
    TestConfig control_tc = TestConfig();
    control_tc.db = control_tc.db+"_control";
    
    Connection control_(control_tc, control_type);
    control = &control_;

    Connection test_(tc, test_type);
    test = &test_;

    RunTest(tc);

    cerr << "RESULT: " << npass << "/" << ntest << endl;
}

