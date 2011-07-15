/*
 * TestSinglePrinc.cpp
 * -- tests single principal overall
 *
 *
 */

#include "TestSinglePrinc.h"

TestSinglePrinc::TestSinglePrinc()
{
    // TODO Auto-generated constructor stub

}

TestSinglePrinc::~TestSinglePrinc()
{
    // TODO Auto-generated destructor stub
}

bool 
equals(ResType a, ResType b)
{
    vector<vector<string> >::iterator ita = a.begin();
    vector<vector<string> >::iterator itb = b.begin();

    vector<string>::iterator itaa;
    vector<string>::iterator itbb;

    if (a.size() != b.size()) {
        return false;
    }

    for(; ita != a.end(); ita++, itb++) {
        itaa = ita->begin();
        itbb = itb->begin();
        if (itaa->size() != itbb->size()) {
            return false;
        }
        for(; itaa != ita->end(); itaa++, itbb++) {
            if (itaa->compare(*itbb) != 0) {
                return false;
            }
        }
    }

    return true;
}

void
PrintRes(ResType res)
{
    for(auto outer = res.begin(); outer != res.end(); outer++) {
        for(auto inner = outer->begin(); inner != outer->end(); inner++) {
            cerr << *inner << " | ";
        }
        cerr << endl;
    }
}

ResType
convert1(string rows[][1], int num_rows) {
  ResType res;
  for (int i = 0; i < num_rows; i++) {
    vector<string> temp;
    for (int j = 0; j < 1; j++) {
      temp.push_back(rows[i][j]);
    }
    res.push_back(temp);
  }
  return res;
}

ResType
convert5(string rows[][5], int num_rows) {
  ResType res;
  for (int i = 0; i < num_rows; i++) {
    vector<string> temp;
    for (int j = 0; j < 5; j++) {
      temp.push_back(rows[i][j]);
    }
    res.push_back(temp);
  }
  return res;
}

void
CheckSelectResults(EDBClient * cl, vector<string> in, vector<ResType> out)
{
    assert_s(
        in.size() == out.size(),
        "different numbers of test queries and expected results");

    vector<string>::iterator query_it = in.begin();
    vector<ResType>::iterator res_it = out.begin();

    while(query_it != in.end()) {
        ResType * test_res = cl->execute(getCStr(*query_it));
        assert_s(test_res,
                 "CheckSelectResults found a query that won't execute");
        if(!equals(*test_res, *res_it)) {
	    cerr << "From query: " << endl;
	    cerr << *query_it << endl;
            cerr << "-----------------------/nExpected result:" << endl;
            PrintRes(*res_it);
            cerr << "Got result:" << endl;
            PrintRes(*test_res);
            assert_s(false, "Select test failed");
        }
        query_it++;
        res_it++;
    }
}

//assumes querys alternate UPDATE, SELECT; only gets results for SELECT
// queries
void
CheckUpdateResults(EDBClient * cl, vector<string> in, vector<ResType> out)
{
    assert_s(
        in.size() == 2*out.size(),
        "different numbers of test queries and expected results");

    vector<string>::iterator query_it = in.begin();
    vector<ResType>::iterator res_it = out.begin();

    while(query_it != in.end()) {
        cl->execute(getCStr(*query_it));
        query_it++;
        ResType * test_res = cl->execute(getCStr(*query_it));
        assert_s(test_res,
                 "CheckUpdateResults found a query that won't execute");
        if(!equals(*test_res, *res_it)) {
            cerr << "Expected result:" << endl;
            PrintRes(*res_it);
            cerr << "Got result:" << endl;
            PrintRes(*test_res);
            assert_s(false, "Update or Delete test failed");
        }
        query_it++;
        res_it++;
    }
}

void
testCreateDrop(EDBClient * cl)
{
    cerr << "createdrop begin" << endl;

    cl->plain_execute("DROP TABLE IF EXISTS table0, table1, table2, table3");
    cerr << "plain okay" << endl;
    string sql = "CREATE TABLE t1 (id integer, words text)";
    assert_s(cl->execute(getCStr(
                             sql)), "Problem creating table t1 (first time)");
    assert_s(cl->plain_execute(
                 "SELECT * FROM table0"),
             "t1 (first time) was not created properly");

    cerr << sql << endl;
    sql =
        "CREATE TABLE t2 (id enc integer, other_id integer, words enc text, other_words text)";
    assert_s(cl->execute(getCStr(
                             sql)), "Problem creating table t2 (first time)");
    assert_s(cl->plain_execute(
                 "SELECT * FROM table1"),
             "t2 (first time) was not created properly");

    sql = "DROP TABLE t1";
    assert_s(cl->execute(getCStr(sql)), "Problem dropping t1");
    assert_s(!cl->plain_execute("SELECT * FROM table0"), "t1 not dropped");
    sql = "DROP TABLE t2";
    assert_s(cl->execute(getCStr(sql)), "Problem dropping t2");
    assert_s(!cl->plain_execute("SELECT * FROM table1"), "t2 not dropped");

    sql = "CREATE TABLE t1 (id integer, words text)";
    assert_s(cl->execute(getCStr(
                             sql)), "Problem creating table t1 (second time)");
    assert_s(cl->plain_execute(
                 "SELECT * FROM table2"),
             "t1 (second time) was not created properly");

    sql =
        "CREATE TABLE t2 (id enc integer, other_id integer, words enc text, other_words text)";
    assert_s(cl->execute(getCStr(
                             sql)), "Problem creating table t2 (second time)");
    assert_s(cl->plain_execute(
                 "SELECT * FROM table3"),
             "t2 (second time) was not created properly");

    assert_s(cl->execute("DROP TABLE t1"), "testSelectDrop won't drop t1");
    assert_s(cl->execute("DROP TABLE t2"), "testSelectDrop won't drop t2");
}

//assumes Select is working
void
testInsert(EDBClient * cl)
{
    cl->plain_execute(
        "DROP TABLE IF EXISTS table0, table1, table2, table3, table4");
    assert_s(cl->execute(
                 "CREATE TABLE t1 (id integer, age enc integer, salary enc integer, address enc text, name text)"),
             "testInsert could not create table");

    vector<string> tests;
    vector<string> results;

    tests.push_back(
        "INSERT INTO t1 VALUES (1, 21, 100, '24 Rosedale, Toronto, ONT', 'Pat Carlson')");
    tests.push_back(
        "INSERT INTO t1 (id, age, salary, address, name) VALUES (1, 21, 100, '24 Rosedale, Toronto, ONT', 'Pat Carlson')");
    tests.push_back(
        "INSERT INTO t1 (age, address, salary, name, id) VALUES (21, '24 Rosedale, Toronto, ONT', 100, 'Pat Carlson', 1)");
    tests.push_back("INSERT INTO t1 (id) VALUES (5)");
    tests.push_back("INSERT INTO t1 (age) VALUES (40)");
    tests.push_back(
        "INSERT INTO t1 (address) VALUES ('right star to the right')");
    tests.push_back("INSERT INTO t1 (name) VALUES ('Wendy')");
    tests.push_back(
        "INSERT INTO t1 (name, address, id, age) VALUES ('Peter Pan', 'second star to the right and straight on till morning', 42, 10)");

    vector<string>::iterator it;
    for (it = tests.begin(); it != tests.end(); it++) {
        assert_s(cl->execute(getCStr(*it)), "sql problem with InsertTest");
    }

    assert_s(cl->execute("DROP TABLE t1"), "testInsert can't drop t1");
}

//assumes Insert is working
void
testSelect(EDBClient * cl)
{
    cl->plain_execute(
        "DROP TABLE IF EXISTS table0, table1, table2, table3, table4, table5");
    assert_s(cl->execute(
                 "CREATE TABLE t1 (id integer, age enc integer, salary enc integer, address enc text, name text)"),
             "testSelect couldn't create table");
    assert_s(cl->execute(
                 "INSERT INTO t1 VALUES (1, 10, 0, 'first star to the right and straight on till morning', 'Peter Pan')"),
             "testSelect couldn't insert (1)");
    assert_s(cl->execute(
                 "INSERT INTO t1 VALUES (2, 16, 1000, 'Green Gables', 'Anne Shirley')"),
             "testSelect couldn't insert (2)");
    assert_s(cl->execute(
                 "INSERT INTO t1 VALUES (3, 8, 0, 'London', 'Lucy')"),
             "testSelect couldn't insert (3)");
    assert_s(cl->execute(
                 "INSERT INTO t1 VALUES (4, 10, 0, 'London', 'Edmund')"),
             "testSelect couldn't insert (4)");
    assert_s(cl->execute(
                 "INSERT INTO t1 VALUES (5, 30, 100000, '221B Baker Street', 'Sherlock Holmes')"),
             "testSelect couldn't insert (5)");

    vector<string> query;
    vector<ResType> reply;

    query.push_back("SELECT * FROM t1");
    string rows1[6][5] = { {"id", "age", "salary", "address", "name"},
                           {"1", "10", "0",
                            "first star to the right and straight on till morning",
                            "Peter Pan"},
                           {"2", "16", "1000", "Green Gables", "Anne Shirley"},
                           {"3", "8", "0", "London", "Lucy"},
                           {"4", "10", "0", "London", "Edmund"},
                           {"5", "30", "100000", "221B Baker Street",
                            "Sherlock Holmes"} };
    reply.push_back(convert5(rows1,6));

    query.push_back("SELECT max(id) FROM t1");
    string rows2[2][1] = { {"max(id)"},
                           {"5"} };
    reply.push_back(convert1(rows2,2));

    query.push_back("SELECT max(salary) FROM t1");
    string rows3[2][1] = { {"max(salary)"},
                           {"100000"} };
    reply.push_back(convert1(rows3,2));

    query.push_back("SELECT COUNT(*) FROM t1");
    string rows4[2][1] = { {"COUNT(*)"},
                           {"5"} };
    reply.push_back(convert1(rows4,2));

    query.push_back("SELECT COUNT(DISTINCT age) FROM t1");
    string rows5[2][1] = { {"COUNT(DISTINCT age)"},
                           {"4"} };
    reply.push_back(convert1(rows5,2));

    query.push_back("SELECT name FROM t1");
    string rows6[6][1] = { {"name"},
                           {"Peter Pan"},
                           {"Anne Shirley"},
                           {"Lucy"},
                           {"Edmund"},
                           {"Sherlock Holmes"} };
    reply.push_back(convert1(rows6,6));

    query.push_back("SELECT address FROM t1");
    string rows7[6][1] = { { "address"},
                           {
                               "first star to the right and straight on till morning"},
                           {"Green Gables"},
                           {"London"},
                           {"London"},
                           {"221B Baker Street"} };
    reply.push_back(convert1(rows7,6));

    query.push_back("SELECT sum(age), max(salary), min(salary), COUNT(name), address FROM t1");
    string rows8[2][5] = { {"sum(age)", "max(salary)", "min(salary)", "COUNT(name)", "address"},
			   {"74",        "100000",     "0",           "5",           "first star to the right and straight on till morning"} };
    reply.push_back(convert5(rows8,2));

    query.push_back("SELECT * FROM t1 WHERE id = 1");
    string rows9[2][5] = { {"id", "age", "salary", "address", "name"},
                           {"1", "10", "0",
                            "first star to the right and straight on till morning",
                            "Peter Pan"} };
    reply.push_back(convert5(rows9,2));

    query.push_back("SELECT * FROM t1 WHERE id>3");
    string rows10[3][5] = { {"id", "age", "salary", "address", "name"},
                            {"4", "10", "0", "London", "Edmund"},
                            {"5", "30", "100000", "221B Baker Street",
                             "Sherlock Holmes"} };
    reply.push_back(convert5(rows10,3));

    query.push_back("SELECT * FROM t1 WHERE age = 8");
    string rows11[2][5] = { {"id", "age", "salary", "address", "name"},
                            {"3", "8", "0", "London", "Lucy"} };
    reply.push_back(convert5(rows11,2));

    query.push_back("SELECT * FROM t1 WHERE salary = 15");
    ResType res;
    res.clear();
    reply.push_back(res);

    query.push_back("SELECT * FROM t1 WHERE age > 10");
    string rows12[3][5] = { {"id", "age", "salary", "address", "name"},
                            {"2", "16", "1000", "Green Gables",
                             "Anne Shirley"},
                            {"5", "30", "100000", "221B Baker Street",
                             "Sherlock Holmes"} };
    reply.push_back(convert5(rows12,3));

    query.push_back("SELECT * FROM t1 WHERE age = 10 AND salary = 0");
    string rows13[3][5] = { {"id", "age", "salary", "address", "name"},
                            {"1", "10", "0",
                             "first star to the right and straight on till morning",
                             "Peter Pan"},
                            {"4", "10", "0", "London", "Edmund"} };
    reply.push_back(convert5(rows13,3));

    query.push_back("SELECT * FROM t1 WHERE age = 10 OR salary = 0");
    string rows14[4][5] = { {"id", "age", "salary", "address", "name"},
                            {"1", "10", "0",
                             "first star to the right and straight on till morning",
                             "Peter Pan"},
                            {"3", "8", "0", "London", "Lucy"},
                            {"4", "10", "0", "London", "Edmund"} };
    reply.push_back(convert5(rows14,4));

    query.push_back("SELECT * FROM t1 WHERE name = 'Peter Pan'");
    string rows15[2][5] = { {"id", "age", "salary", "address", "name"},
                            {"1", "10", "0",
                             "first star to the right and straight on till morning",
                             "Peter Pan"} };
    reply.push_back(convert5(rows15,2));
    //---------------------------------------------------------------------------------

    query.push_back("SELECT * FROM t1 WHERE address= 'Green Gables'");
    string rows16[2][5] = { {"id", "age", "salary", "address", "name"},
                            {"2", "16", "1000", "Green Gables",
                             "Anne Shirley"} };
    reply.push_back(convert5(rows16,2));

    query.push_back("SELECT * FROM t1 WHERE address <= '221C'");
    string rows17[2][5] = { {"id", "age", "salary", "address", "name"},
                            {"5", "30", "100000", "221B Baker Street",
                             "Sherlock Holmes"} };
    reply.push_back(convert5(rows17,2));

    query.push_back(
        "SELECT * FROM t1 WHERE address >= 'Green Gables' AND age > 9");
    string rows18[3][5] = { {"id", "age", "salary", "address", "name"},
                            {"2", "16", "1000", "Green Gables",
                             "Anne Shirley"},
                            {"4", "10", "0", "London", "Edmund"} };
    reply.push_back(convert5(rows18,3));

    query.push_back(
        "SELECT * FROM t1 WHERE address >= 'Green Gables' OR age > 9");
    string rows19[6][5] = { {"id", "age", "salary", "address", "name"},
                            {"1", "10", "0",
                             "first star to the right and straight on till morning",
                             "Peter Pan"},
                            {"2", "16", "1000", "Green Gables",
                             "Anne Shirley"},
                            {"3", "8", "0", "London", "Lucy"},
                            {"4", "10", "0", "London", "Edmund"},
                            {"5", "30", "100000", "221B Baker Street",
                             "Sherlock Holmes"} };
    reply.push_back(convert5(rows19,6));

    query.push_back("SELECT * FROM t1 ORDER BY id");
    string rows20[6][5] = { {"id", "age", "salary", "address", "name"},
                            {"1", "10", "0",
                             "first star to the right and straight on till morning",
                             "Peter Pan"},
                            {"2", "16", "1000", "Green Gables",
                             "Anne Shirley"},
                            {"3", "8", "0", "London", "Lucy"},
                            {"4", "10", "0", "London", "Edmund"},
                            {"5", "30", "100000", "221B Baker Street",
                             "Sherlock Holmes"} };
    reply.push_back(convert5(rows20,6));

    query.push_back("SELECT * FROM t1 ORDER BY salary");
    string rows21[6][5] = { {"id", "age", "salary", "address", "name"},
                            {"1", "10", "0",
                             "first star to the right and straight on till morning",
                             "Peter Pan"},
                            {"3", "8", "0", "London", "Lucy"},
                            {"4", "10", "0", "London", "Edmund"},
                            {"2", "16", "1000", "Green Gables",
                             "Anne Shirley"},
                            {"5", "30", "100000", "221B Baker Street",
                             "Sherlock Holmes"} };
    reply.push_back(convert5(rows21,6));

    query.push_back("SELECT * FROM t1 ORDER BY name");
    string rows22[6][5] = { {"id", "age", "salary", "address", "name"},
                            {"2", "16", "1000", "Green Gables",
                             "Anne Shirley"},
                            {"4", "10", "0", "London", "Edmund"},
                            {"3", "8", "0", "London", "Lucy"},
                            {"1", "10", "0",
                             "first star to the right and straight on till morning",
                             "Peter Pan"},
                            {"5", "30", "100000", "221B Baker Street",
                             "Sherlock Holmes"} };
    reply.push_back(convert5(rows22,6));

    query.push_back("SELECT * FROM t1 ORDER BY address");
    string rows23[6][5] = { {"id", "age", "salary", "address", "name"},
                            {"5", "30", "100000", "221B Baker Street",
                             "Sherlock Holmes"},
                            {"1", "10", "0",
                             "first star to the right and straight on till morning",
                             "Peter Pan"},
                            {"2", "16", "1000", "Green Gables",
                             "Anne Shirley"},
                            {"3", "8", "0", "London", "Lucy"},
                            {"4", "10", "0", "London", "Edmund"} };
    reply.push_back(convert5(rows23,6));

    query.push_back("SELECT * FROM t1 GROUP BY address ORDER BY address");
    string rows24[5][5] = { {"id", "age", "salary", "address", "name"},
                            {"5", "30", "100000", "221B Baker Street",
                             "Sherlock Holmes"},
                            {"1", "10", "0",
                             "first star to the right and straight on till morning",
                             "Peter Pan"},
                            {"2", "16", "1000", "Green Gables",
                             "Anne Shirley"},
                            {"3", "8", "0", "London", "Lucy"} };
    reply.push_back(convert5(rows24,5));

    query.push_back("SELECT * FROM t1 GROUP BY age ORDER BY age");
    string rows25[5][5] = { {"id", "age", "salary", "address", "name"},
                            {"3", "8", "0", "London", "Lucy"},
                            {"1", "10", "0",
                             "first star to the right and straight on till morning",
                             "Peter Pan"},
                            {"2", "16", "1000", "Green Gables",
                             "Anne Shirley"},
                            {"5", "30", "100000", "221B Baker Street",
                             "Sherlock Holmes"} };
    reply.push_back(convert5(rows25,5));

    CheckSelectResults(cl, query, reply);

    cl->execute("DROP TABLE t1;");
}

//assumes Select works
void
testUpdate(EDBClient * cl)
{
    cl->plain_execute(
        "DROP TABLE IF EXISTS table0, table1, table2, table3, table4, table5, table6");
    assert_s(cl->execute(
                 "CREATE TABLE t1 (id integer, age enc integer, salary enc integer, address enc text, name text)"),
             "testSelect couldn't create table");
    assert_s(cl->execute(
                 "INSERT INTO t1 VALUES (1, 10, 0, 'first star to the right and straight on till morning', 'Peter Pan')"),
             "testUpdate couldn't insert (1)");
    assert_s(cl->execute(
                 "INSERT INTO t1 VALUES (2, 16, 1000, 'Green Gables', 'Anne Shirley')"),
             "testUpdate couldn't insert (2)");
    assert_s(cl->execute(
                 "INSERT INTO t1 VALUES (3, 8, 0, 'London', 'Lucy')"),
             "testUpdate couldn't insert (3)");
    assert_s(cl->execute(
                 "INSERT INTO t1 VALUES (4, 10, 0, 'London', 'Edmund')"),
             "testUpdate couldn't insert (4)");
    assert_s(cl->execute(
                 "INSERT INTO t1 VALUES (5, 30, 100000, '221B Baker Street', 'Sherlock Holmes')"),
             "testUpdate couldn't insert (5)");
    assert_s(cl->execute(
                 "INSERT INTO t1 (id) VALUES (6)"),
             "testUpdate couldn't insert (6)");

    vector<string> query;
    vector<ResType> reply;

    ResType res;

    query.push_back("UPDATE t1 SET salary=0");
    query.push_back("SELECT * FROM t1");
    string rows1[7][5] = { {"id", "age", "salary", "address", "name"},
                           {"1", "10", "0",
                            "first star to the right and straight on till morning",
                            "Peter Pan"},
                           {"2", "16", "0", "Green Gables", "Anne Shirley"},
                           {"3", "8", "0", "London", "Lucy"},
                           {"4", "10", "0", "London", "Edmund"},
                           {"5", "30", "0", "221B Baker Street",
                            "Sherlock Holmes"},
                           {"6", NULL, "0", NULL, NULL} };
    reply.push_back(convert5(rows1,7));

    query.push_back("UPDATE t1 SET age=21 WHERE id6");
    query.push_back("SELECT * FROM t1");
    string rows2[7][5] = { {"id", "age", "salary", "address", "name"},
                           {"1", "10", "0",
                            "first star to the right and straight on till morning",
                            "Peter Pan"},
                           {"2", "16", "0", "Green Gables", "Anne Shirley"},
                           {"3", "8", "0", "London", "Lucy"},
                           {"4", "10", "0", "London", "Edmund"},
                           {"5", "30", "0", "221B Baker Street",
                            "Sherlock Holmes"},
                           {"6", "21", "0", NULL, NULL} };
    reply.push_back(convert5(rows2,7));

    query.push_back(
        "UPDATE t1 SET address='Pemberly', name='Elizabeth Darcy' WHERE id=6");
    query.push_back("SELECT * FROM t1");
    string rows3[7][5] = { {"id", "age", "salary", "address", "name"},
                           {"1", "10", "0",
                            "first star to the right and straight on till morning",
                            "Peter Pan"},
                           {"2", "16", "0", "Green Gables", "Anne Shirley"},
                           {"3", "8", "0", "London", "Lucy"},
                           {"4", "10", "0", "London", "Edmund"},
                           {"5", "30", "0", "221B Baker Street",
                            "Sherlock Holmes"},
                           {"6", "21", "0", "Pemberly", "Elizabeth Darcy"} };
    reply.push_back(convert5(rows3,7));

    query.push_back("UPDATE t1 SET salary=55000 WHERE age=30");
    query.push_back("SELECT * FROM t1");
    string rows4[7][5] = { {"id", "age", "salary", "address", "name"},
                           {"1", "10", "0",
                            "first star to the right and straight on till morning",
                            "Peter Pan"},
                           {"2", "16", "0", "Green Gables", "Anne Shirley"},
                           {"3", "8", "0", "London", "Lucy"},
                           {"4", "10", "0", "London", "Edmund"},
                           {"5", "30", "55000", "221B Baker Street",
                            "Sherlock Holmes"},
                           {"6", "21", "0", "Pemberly", "Elizabeth Darcy"} };
    reply.push_back(convert5(rows4,7));
    
    query.push_back("UPDATE t1 SET salary=20000 WHERE address='Pemberly'");
    query.push_back("SELECT * FROM t1");
    string rows5[7][5] = { {"id", "age", "salary", "address", "name"},
                           {"1", "10", "0",
                            "first star to the right and straight on till morning",
                            "Peter Pan"},
                           {"2", "16", "0", "Green Gables", "Anne Shirley"},
                           {"3", "8", "0", "London", "Lucy"},
                           {"4", "10", "0", "London", "Edmund"},
                           {"5", "30", "55000", "221B Baker Street",
                            "Sherlock Holmes"},
                           {"6", "21", "0", "Pemberly", "Elizabeth Darcy"} };
    reply.push_back(convert5(rows5,7));

    CheckUpdateResults(cl, query, reply);

    cl->execute("DROP TABLE t1;");
}

void
testDelete(EDBClient * cl)
{
    cl->plain_execute(
        "DROP TABLE IF EXISTS table0, table1, table2, table3, table4, table5, table6");
    assert_s(cl->execute(
                 "CREATE TABLE t1 (id integer, age enc integer, salary enc integer, address enc text, name text)"),
             "testSelect couldn't create table");
    assert_s(cl->execute(
                 "INSERT INTO t1 VALUES (1, 10, 0, 'first star to the right and straight on till morning', 'Peter Pan')"),
             "testUpdate couldn't insert (1)");
    assert_s(cl->execute(
                 "INSERT INTO t1 VALUES (2, 16, 1000, 'Green Gables', 'Anne Shirley')"),
             "testUpdate couldn't insert (2)");
    assert_s(cl->execute(
                 "INSERT INTO t1 VALUES (3, 8, 0, 'London', 'Lucy')"),
             "testUpdate couldn't insert (3)");
    assert_s(cl->execute(
                 "INSERT INTO t1 VALUES (4, 10, 0, 'London', 'Edmund')"),
             "testUpdate couldn't insert (4)");
    assert_s(cl->execute(
                 "INSERT INTO t1 VALUES (5, 30, 100000, '221B Baker Street', 'Sherlock Holmes')"),
             "testUpdate couldn't insert (5)");
    assert_s(cl->execute(
                 "INSERT INTO t1 VALUES (6, 21, 20000, 'Pemberly', 'Elizabeth Darcy')"),
             "testUpdate couldn't insert (6)");
    assert_s(cl->execute(
                 "INSERT INTO t1 VALUES (7, 10000, 1, 'Mordor', 'Sauron')"),
             "testUpdate couldn't insert (7)");
    assert_s(cl->execute(
                 "INSERT INTO t1 VALUES (8, 25, 100, 'The Heath', 'Eustacia Vye')"),
             "testUpdate couldn't insert (8)");

    vector<string> query;
    vector<ResType> reply;

    ResType res;

    query.push_back("DELETE FROM t1 WHERE id=1");
    query.push_back("SELECT * FROM t1");
    string rows1[8][5] = { {"id", "age", "salary", "address", "name"},
                           {"2", "16", "1000", "Green Gables", "Anne Shirley"},
                           {"3", "8", "0", "London", "Lucy"},
                           {"4", "10", "0", "London", "Edmund"},
                           {"5", "30", "100000", "221B Baker Street",
                            "Sherlock Holmes"},
                           {"6", "21", "20000", "Pemberly", "Elizabeth Darcy"},
                           {"7", "10000", "1", "Mordor", "Sauron"},
                           {"8", "25", "100", "The Heath", "Eustacia Vye"} };
    reply.push_back(convert5(rows1,8));

    query.push_back("DELETE FROM t1 WHERE age=30");
    query.push_back("SELECT * FROM t1");
    string rows2[7][5] = { {"id", "age", "salary", "address", "name"},
                           {"2", "16", "1000", "Green Gables", "Anne Shirley"},
                           {"3", "8", "0", "London", "Lucy"},
                           {"4", "10", "0", "London", "Edmund"},
                           {"6", "21", "20000", "Pemberly", "Elizabeth Darcy"},
                           {"7", "10000", "1", "Mordor", "Sauron"},
                           {"8", "25", "100", "The Heath", "Eustacia Vye"} };
    reply.push_back(convert5(rows2,7));

    query.push_back("DELETE FROM t1 WHERE name='Eustacia Vye'");
    query.push_back("SELECT * FROM t1");
    string rows3[6][5] = { {"id", "age", "salary", "address", "name"},
                           {"2", "16", "1000", "Green Gables", "Anne Shirley"},
                           {"3", "8", "0", "London", "Lucy"},
                           {"4", "10", "0", "London", "Edmund"},
                           {"6", "21", "20000", "Pemberly", "Elizabeth Darcy"},
                           {"7", "10000", "1", "Mordor", "Sauron"} };
    reply.push_back(convert5(rows3,6));

    query.push_back("DELETE FROM t1 WHERE address='London'");
    query.push_back("SELECT * FROM t1");
    string rows4[4][5] = { {"id", "age", "salary", "address", "name"},
                           {"2", "16", "1000", "Green Gables", "Anne Shirley"},
                           {"6", "21", "20000", "Pemberly", "Elizabeth Darcy"},
                           {"7", "10000", "1", "Mordor", "Sauron"} };
    reply.push_back(convert5(rows4,4));

    query.push_back("DELETE FROM t1 WHERE salary=1");
    query.push_back("SELECT * FROM t1");
    string rows5[3][5] = { {"id", "age", "salary", "address", "name"},
                           {"2", "16", "1000", "Green Gables", "Anne Shirley"},
                           {"6", "21", "20000", "Pemberly", "Elizabeth Darcy"} };
    reply.push_back(convert5(rows5,3));

    query.push_back("DELETE FROM t1");
    query.push_back("SELECT * FROM t1");
    reply.push_back(res);

    query.push_back(
        "INSERT INTO t1 VALUES (1, 10, 0, 'first star to the right and straight on till morning', 'Peter Pan')");
    query.push_back("SELECT * FROM t1");
    string rows6[2][5] = { {"id", "age", "salary", "address", "name"},
                           {"1", "10", "0",
                            "first star to the right and straight on till morning",
                            "Peter Pan"} };
    reply.push_back(convert5(rows6,2));

    query.push_back("DELETE * FROM t1");
    query.push_back("SELECT * FROM t1");
    reply.push_back(res);

    CheckUpdateResults(cl, query, reply);

    cl->execute("DROP TABLE t1");
}

void
TestSinglePrinc::run(int argc, char ** argv)
{
    EDBClient * cl;
    uint64_t mkey = 113341234;
    string masterKey = BytesFromInt(mkey, AES_KEY_BYTES);
    cl = new EDBClient("localhost", "root", "letmein", "mysql", masterKey);
    assert_s(MULTIPRINC == 0,
             "MULTIPRINC is on.  Please set it to 0 (in params.h)");

    cerr << "Testing create and drop..." << endl;
    testCreateDrop(cl);
    cerr << "Testing insert..." << endl;
    testInsert(cl);
    cerr << "Testing select..." << endl;
    testSelect(cl);
    cerr << "Testing update..." << endl;
    testUpdate(cl);
    cerr << "Testing delete..." << endl;
    testDelete(cl);
    cerr << "Done!  All single-princ tests passed." << endl;
}
