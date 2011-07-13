/*
 * TestSinglePrinc.cpp
 * -- tests single principal overall
 *
 *
 */

#include "TestSinglePrinc.h"

TestSinglePrinc::TestSinglePrinc() {
	// TODO Auto-generated constructor stub

}

TestSinglePrinc::~TestSinglePrinc() {
	// TODO Auto-generated destructor stub
}

bool equals(ResType a, ResType b) {
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

void CheckResults(EDBClient * cl, vector<string> in, vector<ResType> out) {
  assert_s(in.size() == out.size(), "different numbers of test queries and expected results");

  vector<string>::iterator query_it = in.begin();
  vector<ResType>::iterator res_it = out.begin();

  for(; query_it != in.end(); query_it++, res_it++) {
    ResType * test_res = cl->execute(getCStr(*query_it));
    assert_s(test_res, "CheckResults found a query that won't execute");
    assert_s(equals(*test_res, *res_it), "unexpected result");
  }
}

void testCreateDrop(EDBClient * cl) {
  cl->plain_execute("DROP TABLE IF EXISTS table0, table1, table2, table3");
  string sql = "CREATE TABLE t1 (id integer, words text)";
  assert_s(cl->execute(getCStr(sql)), "Problem creating table t1 (first time)");
  assert_s(cl->plain_execute("SELECT * FROM table0"), "t1 (first time) was not created properly");

  cerr << sql << endl;
  sql = "CREATE TABLE t2 (id enc integer, other_id integer, words enc text, other_words text)";
  assert_s(cl->execute(getCStr(sql)), "Problem creating table t2 (first time)");
  assert_s(cl->plain_execute("SELECT * FROM table1"), "t2 (first time) was not created properly");

  sql = "DROP TABLE t1";
  assert_s(cl->execute(getCStr(sql)), "Problem dropping t1");
  assert_s(!cl->plain_execute("SELECT * FROM table0"), "t1 not dropped");
  sql = "DROP TABLE t2";
  assert_s(cl->execute(getCStr(sql)), "Problem dropping t2");
  assert_s(!cl->plain_execute("SELECT * FROM table1"), "t2 not dropped");

  sql = "CREATE TABLE t1 (id integer, words text)";
  assert_s(cl->execute(getCStr(sql)), "Problem creating table t1 (second time)");
  assert_s(cl->plain_execute("SELECT * FROM table2"), "t1 (second time) was not created properly");

  sql = "CREATE TABLE t2 (id enc integer, other_id integer, words enc text, other_words text)";
  assert_s(cl->execute(getCStr(sql)), "Problem creating table t2 (second time)");
  assert_s(cl->plain_execute("SELECT * FROM table3"), "t2 (second time) was not created properly");
  
  assert_s(cl->execute("DROP TABLE t1"), "testSelectDrop won't drop t1");
  assert_s(cl->execute("DROP TABLE t2"), "testSelectDrop won't drop t2");
}

//assumes Select is working
void testInsert(EDBClient * cl) {
  cl->plain_execute("DROP TABLE IF EXISTS table0, table1, table2, table3, table4");
  assert_s(cl->execute("CREATE TABLE t1 (id integer, age enc integer, salary enc integer, address enc text, name text)"), "testInsert could not create table");

  vector<string> tests;
  vector<string> results;

  tests.push_back("INSERT INTO t1 VALUES (1, 21, 100, '24 Rosedale, Toronto, ONT', 'Pat Carlson')");
  tests.push_back("INSERT INTO t1 (id, age, salary, address, name) VALUES (1, 21, 100, '24 Rosedale, Toronto, ONT', 'Pat Carlson')");
  tests.push_back("INSERT INTO t1 (age, address, salary, name, id) VALUES (21, '24 Rosedale, Toronto, ONT', 100, 'Pat Carlson', 1)");
  tests.push_back("INSERT INTO t1 (id) VALUES (5)");
  tests.push_back("INSERT INTO t1 (age) VALUES (40)");
  tests.push_back("INSERT INTO t1 (address) VALUES ('right star to the right')");
  tests.push_back("INSERT INTO t1 (name) VALUES ('Wendy')");
  tests.push_back("INSERT INTO t1 (name, address, id, age) VALUES ('Peter Pan', 'second star to the right and straight on till morning', 42, 10)");

  vector<string>::iterator it;
  for (it = tests.begin(); it != tests.end(); it++) {
    assert_s(cl->execute(getCStr(*it)), "sql problem with InsertTest");
  }

  assert_s(cl->execute("DROP TABLE t1"), "testInsert can't drop t1");
}

//assumes Insert is working
void testSelect(EDBClient * cl) {
  cl->plain_execute("DROP TABLE IF EXISTS table0, table1, table2, table3, table4, table5");
  assert_s(cl->execute("CREATE TABLE t1 (id integer, age enc integer, salary enc integer, address enc text, name text)"), "testSelect couldn't create table");
  assert_s(cl->execute("INSERT INTO t1 VALUES (1, 10, 0, 'first star to the right and straight on till morning', 'Peter Pan')"), "testSelect couldn't insert (1)");
  assert_s(cl->execute("INSERT INTO t1 VALUES (2, 16, 1000, 'Green Gables, 'Anne Shirley')"), "testSelect couldn't insert (2)");
  assert_s(cl->execute("INSERT INTO t1 VALUES (3, 8, 0, 'London', 'Lucy')"), "testSelect couldn't insert (3)");
  assert_s(cl->execute("INSERT INTO t1 VALUES (4, 10, 0, 'London', 'Edmund')"), "testSelect couldn't insert (4)");
  assert_s(cl->execute("INSERT INTO t1 VALUES (5, 30, 100000, '221B Baker Street', 'Sherlock Holmes')"), "testSelect couldn't insert (5)");


  vector<string> query;
  vector<ResType> reply;


  query.push_back("SELECT * FROM t1");
  string rows1[6][5] = { {"id", "age", "salary", "address", "name"},
			{"1", "10", "0", "first star to the right and straight on till morning", "Peter Pan"},
			{"2", "16", "1000", "Green Gables", "Anne Shirley"},
			{"3", "8", "0", "London", "Lucy"},
			{"4", "10", "0", "London", "Edmund"},
			{"5", "30", "100000", "221B Baker Street", "Sherlock Holmes"} };
  ResType res;
  for (int i = 0; i < 6; i++) {
    vector<string> temp;
    for (int j = 0; j < 5; j++) {
      temp.push_back(rows1[i][j]);
    }
    res.push_back(temp);
  }
  reply.push_back(res);
  res.clear();

  query.push_back("SELECT max(id) FROM t1");
  string rows2[2][1] = { {"id"},
			{"5"} };
  for (int i = 0; i < 2; i++) {
    vector<string> temp;
    for (int j = 0; j < 1; j++) {
      temp.push_back(rows2[i][j]);
    }
    res.push_back(temp);
  }
  reply.push_back(res);
  res.clear();

  query.push_back("SELECT max(salary) FROM t1");
  string rows3[2][1] = { {"salary"},
			{"100000"} };
  for (int i = 0; i < 2; i++) {
    vector<string> temp;
    for (int j = 0; j < 1; j++) {
      temp.push_back(rows3[i][j]);
    }
    res.push_back(temp);
  }
  reply.push_back(res);
  res.clear();


  query.push_back("SELECT COUNT(*) FROM t1");
  string rows4[2][1] = { {"COUNT(*)"},
			{"5"} };
  for (int i = 0; i < 2; i++) {
    vector<string> temp;
    for (int j = 0; j < 1; j++) {
      temp.push_back(rows4[i][j]);
    }
    res.push_back(temp);
  }
  reply.push_back(res);
  res.clear();

  query.push_back("SELECT COUNT(DISTINCT age) FROM t1");
  string rows5[2][1] = { {"COUNT(DISTINCT age)"},
			{"4"} };
  for (int i = 0; i < 2; i++) {
    vector<string> temp;
    for (int j = 0; j < 1; j++) {
      temp.push_back(rows5[i][j]);
    }
    res.push_back(temp);
  }
  reply.push_back(res);
  res.clear();
  query.push_back("SELECT (name) FROM t1");
  string rows6[6][1] = { {"name"},
		       {"Peter Pan"},
		       {"Anne Shirley"},
		       {"Lucy"},
		       {"Edmund"},
		       {"Sherlock Holmes"} };
  for (int i = 0; i < 6; i++) {
    vector<string> temp;
    for (int j = 0; j < 1; j++) {
      temp.push_back(rows6[i][j]);
    }
    res.push_back(temp);
  }
  reply.push_back(res);
  res.clear();

  query.push_back("SELECT (address) FROM t1");
  string rows7[6][1] = { { "address"},
			{"first star to the right and straight on till morning"},
			{"Green Gables"},
			{"London"},
			{"London"},
			{"221B Baker Street"} };
  for (int i = 0; i < 6; i++) {
    vector<string> temp;  
    for (int j = 0; j < 1; j++) {
      temp.push_back(rows7[i][j]);
    }
    res.push_back(temp);
  }
  reply.push_back(res);
  res.clear();

  query.push_back("SELECT sum(age), max(address), min(salary), COUNT(name), salary FROM t1");

  string rows8[2][5] = { {"sum(age)", "max(address)", "min(salary)", "COUNT(name)", "salary"},
		       {"76", "London", "0", "5", "0"} };
  for (int i = 0; i < 2; i++) {
    vector<string> temp;
    for (int j = 0; j < 5; j++) {
      temp.push_back(rows8[i][j]);
    }
    res.push_back(temp);
  }
  reply.push_back(res);
  res.clear();
  
  //TODO Where statements

  CheckResults(cl, query, reply);
}

void testUpdate(EDBClient * cl) {

}

void testDelete(EDBClient * cl) {

}


void TestSinglePrinc::run(int argc, char ** argv) {
        EDBClient * cl;
	uint64_t mkey = 113341234;
	unsigned char * masterKey = BytesFromInt(mkey, AES_KEY_BYTES);
	cl = new EDBClient("localhost", "root", "letmein", "mysql", masterKey);

	assert_s(MULTIPRINC == 0, "MULTIPRINC is on.  Please set it to 0 (in params.h)");

	testCreateDrop(cl);
	testInsert(cl);
	testSelect(cl);
	testUpdate(cl);
	testDelete(cl);
}
