/*
 * TestAccessManager
 * -- tests KeyAccess and MetaAccess
 *
 *
 */

#include "TestAccessManager.h"

static int ntest = 0;
static int npass = 0;

static void
record(const TestConfig &tc, bool result, string test) {
    ntest++;
    if (!result) {
      if (tc.stop_if_fail) {
	assert_s(false,test);
      }
      return;
    }
    npass++;
}

static Prin alice = Prin("u.uname","alice");
static Prin bob = Prin("u.uname","bob");
static Prin chris = Prin("u.uname","chris");

static Prin u1 = Prin("u.uid","1");
static Prin u2 = Prin("u.uid","2");
static Prin u3 = Prin("u.uid","3");

static Prin g5 = Prin("g.gid","5");

static Prin f2 = Prin("f.fid","2");
static Prin f3 = Prin("f.fid","3");

static Prin mlwork = Prin("x.mailing_list","work");

static Prin a5 = Prin("u.acc","5");

static Prin m2 = Prin("m.mess","2");
static Prin m3 = Prin("m.mess","3");
static Prin m4 = Prin("m.mess","4");
static Prin m5 = Prin("m.mess","5");
static Prin m15 = Prin("m.mess","15");

static Prin s4 = Prin("m.sub","4");
static Prin s5 = Prin("m.sub","5");
static Prin s6 = Prin("m.sub","6");
static Prin s7 = Prin("m.sub","7");
static Prin s24 = Prin("m.sub","24");

static string secretA = "secretA";
static string secretB = "secretB";
static string secretC = "secretC";

TestAccessManager::TestAccessManager() {}

TestAccessManager::~TestAccessManager() {}

static void
testMeta_native(const TestConfig &tc, Connect * conn) {
    string test = "(native meta) ";
    MetaAccess * meta;
    meta = new MetaAccess(conn, false);
    
    meta->addEquals("u.uid","g.guid");
    meta->addAccess("u.uid","g.gid");
    
    record(tc, !meta->CheckAccess(), test + "CheckAccess--no gives");
    
    meta->addGives("u.uname");
    
    record(tc, !meta->CheckAccess(), test + "CheckAccess--bad tree");
    
    meta->addAccess("u.uname","u.uid");
    
    record(tc, meta->CheckAccess(), test + "CheckAccess--good tree");  
    
    delete meta;
}

static KeyAccess *
buildTest(Connect * conn) {
    KeyAccess * am;
    am = new KeyAccess(conn);
  
    am->addEquals("u.uid","g.uid");
    am->addAccess("u.uname","u.uid");
    am->addEquals("m.uid","u.uid");
    am->addAccess("m.uid","m.mess");
    am->addAccess("u.uid","u.acc");
    am->addAccess("g.uid","g.gid");
    am->addEquals("g.gid","x.gid");
    am->addAccess("f.gid","f.fid");
    am->addAccess("x.gid","x.mailing_list");
    am->addEquals("g.gid","f.gid");
    am->addAccess("m.mess","m.sub");
    am->addAccess("f.gid","u.acc");
    am->addGives("u.uname");
    am->addAccess("msgs.msgid", "msgs.msgtext");
    am->addEquals("msgs.msgid","privmsgs.msgid");
    am->addEquals("privmsgs.recid", "users.userid");
    am->addAccess("privmsgs.recid", "privmsgs.msgid");
    am->addAccess("privmsgs.senderid", "privmsgs.msgid");
    am->addEquals("users.userid", "privmsgs.senderid");
    am->addGives("users.username");
    am->addAccess("users.username", "users.userid");

    secretA.resize(AES_KEY_BYTES);
    secretB.resize(AES_KEY_BYTES);
    secretC.resize(AES_KEY_BYTES);
    
    assert_s(am->CreateTables() == 0, "could not create tables");

    return am;
}

//assumes ka has been built with buildTest
static void
buildBasic(KeyAccess * am) {
    am->insertPsswd(alice,secretA);
    am->insert(alice,u1);
    am->insert(u1,g5);
    am->insert(g5,mlwork);
    am->insert(g5,f2);
    am->insert(g5,f3);
    am->insertPsswd(bob,secretB);
    am->insert(bob,u2);
    am->insert(u2,g5);
    am->removePsswd(alice);
    am->removePsswd(bob);
}

static void
testMeta(const TestConfig &tc, KeyAccess * am) {
    string test = "(meta) ";

    std::set<string> generic_gid = am->getEquals("g.gid");
    record(tc, generic_gid.find("f.gid") != generic_gid.end(), test+"f.gid not in getEquals(g.gid)");
    record(tc, generic_gid.find("x.gid") != generic_gid.end(), test+"x.gid not in getEquals(g.gid)");
    
    std::set<string> generic_uid = am->getEquals("m.uid");
    record(tc, generic_uid.find("u.uid") != generic_uid.end(), test+"u.uid not in getEquals(m.uid)");
    record(tc, generic_uid.find("g.uid") != generic_uid.end(), test+"g.uid not in getEquals(m.uid)");
    record(tc, generic_uid.find("f.gid") == generic_uid.end(), test+"m.uid in getEquals(f.gid)");
    
    std::set<string> gid_hasAccessTo = am->getTypesHasAccessTo("g.gid");
    record(tc, gid_hasAccessTo.find("f.fid") != gid_hasAccessTo.end(), test+"g.gid does not have access to f.fid");
    record(tc, gid_hasAccessTo.find("x.mailing_list") != gid_hasAccessTo.end(),test+"g.gid does not have access to x.mailing_list");
    record(tc, gid_hasAccessTo.find("g.uid") == gid_hasAccessTo.end(),test+"g.gid does have access to g.uid");
    record(tc, gid_hasAccessTo.find(
				"f.gid") == gid_hasAccessTo.end(),
	   test+"getTypesHasAccessTo(g.gid) includes f.gid");
    record(tc, gid_hasAccessTo.find(
				"g.gid") == gid_hasAccessTo.end(),
	 test+"getTypesHasAccessTo(g.gid) includes g.gid");
    
    std::set<string> mess_accessibleFrom = am->getTypesAccessibleFrom("m.mess");
    record(tc, mess_accessibleFrom.find(
				    "m.uid") != mess_accessibleFrom.end(),
	   test+"m.mess is not accessible from m.uid");
    record(tc, mess_accessibleFrom.find(
				    "u.uid") != mess_accessibleFrom.end(),
	   test+"m.mess is not accessible from u.uid");
    record(tc, mess_accessibleFrom.find(
				    "g.uid") != mess_accessibleFrom.end(),
	 test+"m.mess is not accessible from g.uid");
    record(tc, mess_accessibleFrom.find(
				    "g.gid") == mess_accessibleFrom.end(),
	   test+"m.mess is accessible from g.gid");
    record(tc, mess_accessibleFrom.find(
				    "u.uname") == mess_accessibleFrom.end(),
	   test+"m.mess is accessible from u.uname in one link");
    
    std::set<string> acc_accessibleFrom = am->getGenAccessibleFrom(
								   am->getGeneric("u.acc"));
    record(tc, acc_accessibleFrom.find(am->getGeneric(
						  "u.uid")) != acc_accessibleFrom.end(),
	   test+"gen acc is not accessible from gen uid");
    record(tc, acc_accessibleFrom.find(am->getGeneric(
						  "g.gid")) != acc_accessibleFrom.end(),
	   test+"gen acc is not accessible from gen gid");
    record(tc, acc_accessibleFrom.find(am->getGeneric(
						  "f.fid")) == acc_accessibleFrom.end(),
	   test+"gen acc is accessible from gen fid");
    
    list<string> bfs = am->BFS_hasAccess(alice);
    list<string> dfs = am->DFS_hasAccess(alice);
    
    record(tc, bfs.size() == dfs.size(), test + "bfs and dfs have different sizes");
    
}

static void
testSingleUser(const TestConfig &tc, KeyAccess * am) {
    string test = "(single) ";

    record(tc, am->insertPsswd(alice,secretA) == 0, "insert alice failed");

    am->insert(alice, u1);
    am->insert(u1, g5);
    am->insert(g5,f2);
    string f2_key1 = marshallBinary(am->getKey(f2));
    record(tc, f2_key1.length() > 0, test + "alice cannot access forumkey");
    am->removePsswd(alice);
    record(tc, am->getKey(alice).length() == 0, test + "alice's key accesible with no one logged on");
    record(tc, am->getKey(u1).length() == 0, test + "u1's key accesible with no one logged on");
    record(tc, am->getKey(g5).length() == 0, test + "g5's key accesible with no one logged on");
    record(tc, am->getKey(f2).length() == 0, test + "f2's key accesible with no one logged on");
    am->insertPsswd(alice,secretA);
    string f2_key2 = marshallBinary(am->getKey(f2));
    record(tc, f2_key2.length() > 0, test + "alice cannot access forumkey");
    record(tc, f2_key1.compare(f2_key2) == 0, test + "forum keys are not equal for alice");
}

static void
testMultiBasic(const TestConfig &tc, KeyAccess * am) {
    string test = "(multi basic) ";
    am->insertPsswd(alice,secretA);
    am->insert(alice,u1);
    am->insert(u1,g5);
    am->insert(g5,f2);
    string f2_key1 = marshallBinary(am->getKey(f2));
    am->insertPsswd(bob,secretB);
    am->insert(bob,u2);
    am->insert(u2,g5);

    record(tc, am->getKey(f2).length() > 0,
	   test+"forum 2 key not accessible with both alice and bob logged on");
    am->removePsswd(alice);
    string f2_key2 = marshallBinary(am->getKey(f2));
    record(tc, f2_key2.length() > 0,
	   test+"forum 2 key not accessible with bob logged on");
    record(tc, f2_key2.compare(f2_key1) == 0,
	   test+"forum 2 key is not the same for bob as it was for alice");
    am->insert(g5,f3);
    string f3_key1 = marshallBinary(am->getKey(f3));
    record(tc, f3_key1.length() > 0,
	   test+"forum 3 key not acessible with bob logged on");
    am->removePsswd(bob);
    record(tc, am->getKey(alice).length() == 0,
	   test+"can access alice's key with no one logged in");
    record(tc, am->getKey(bob).length() == 0,
	   test+"can access bob's key with no one logged in");
    record(tc, am->getKey(u1).length() == 0,
	   test+"can access user 1 key with no one logged in");
    record(tc, am->getKey(u2).length() == 0,
	   test+"can access user 2 key with no one logged in");
    record(tc, am->getKey(g5).length() == 0,
	   test+"can access group 5 key with no one logged in");
    record(tc, am->getKey(f2).length() == 0,
	   test+"can access forum 2 key with no one logged in");
    record(tc, am->getKey(f3).length() == 0,
	   test+"can access forum 3 key with no one logged in");
    am->insertPsswd(alice, secretA);
    string f3_key2 = marshallBinary(am->getKey(f3));
    record(tc, f3_key2.length() > 0,
	   test+"forum 3 key not accessible with alice logged on");
    record(tc, f3_key1.compare(f3_key2) == 0,
	   test+"forum 3 key is not the same for alice as it was for bob");
    am->removePsswd(alice);
    am->insert(g5,mlwork);
    record(tc, am->getKey(mlwork).length() == 0,
	   test+"can access mailing list work key with no one logged in");
    record(tc, am->insertPsswd(alice, secretA) == 0, "insert alice failed (4)");
    string work_key1 = marshallBinary(am->getKey(mlwork));
    record(tc, work_key1.length() > 0,
	   test+"mailing list work key inaccessible when alice is logged on");
    am->removePsswd(alice);
    am->insertPsswd(bob, secretB);
    string work_key2 = marshallBinary(am->getKey(mlwork));
    record(tc, work_key2.length() > 0,
	   test+"mailing list work key inaccessible when bob is logged on");
    record(tc, work_key1.compare(work_key2) == 0,
	   test+"mailing list work key is not the same for bob as it was for alice");
}

static void
testNonTree(const TestConfig &tc, KeyAccess * am) {
    string test = "(non-tree) ";
    buildBasic(am);

    am->insert(g5,a5);
    record(tc, am->getKey(a5).length() == 0,
	   test+"can access a5's key with no one logged in");
    am->insertPsswd(alice,secretA);
    string a5_key1 = marshallBinary(am->getKey(a5));
    record(tc, a5_key1.length() > 0,
	   test+"cannot access a5's key with alice logged on");
    am->removePsswd(alice);
    am->insertPsswd(bob,secretB);
    string a5_key2 = marshallBinary(am->getKey(a5));\
    record(tc, a5_key2.length() > 0,
	   test+"cannot access a5's key with bob logged on");
    record(tc, a5_key1.compare(a5_key2) == 0,
	   test+"alice and bob have different a5 keys");

}

static void
testOrphans(const TestConfig &tc, KeyAccess * am) {
    string test = "(orphan) ";
    buildBasic(am);
    am->insertPsswd(bob,secretB);
    am->insert(g5,a5);
    am->removePsswd(bob);

    am->insert(m2,s6);
    record(tc, (am->getKey(s6)).length() > 0,
	   test+"s6 key does not exist as an orphan");
    record(tc, (am->getKey(m2)).length() > 0,
	   test+"m2 key does not exist as an orphan");
    string s6_key1 = marshallBinary(am->getKey(s6));
    string m2_key1 = marshallBinary(am->getKey(m2));

    am->insert(u2,m2);
    record(tc, (am->getKey(m2)).length() == 0,
	   test+"m2 key is available when bob is logged off");
    record(tc, (am->getKey(s6)).length() == 0,
	   test+"s6 key is available when bob is logged off");
    
    am->insertPsswd(bob,secretB);
    record(tc, (am->getKey(s6)).length() > 0,
	   test+"s6 key is not available when bob is logged on");
    record(tc, (am->getKey(m2)).length() > 0,
	   test+"m2 key is not available when bob is logged on");
    string s6_key3 = marshallBinary(am->getKey(s6));
    string m2_key3 = marshallBinary(am->getKey(m2));
    record(tc, s6_key1.compare(s6_key3) == 0, test+"s6 key does not match");
    record(tc, m2_key1.compare(m2_key3) == 0, test+"m2 key does not match");

    am->insert(m3,s4);
    record(tc, (am->getKey(s4)).length() > 0,
	   test+"s4 key does not exist as an orphan");
    record(tc, (am->getKey(m3)).length() > 0,
	   test+"m3 key does not exist as an orphan");
    string s4_key1 = marshallBinary(am->getKey(s4));
    string m3_key1 = marshallBinary(am->getKey(m3));
    am->insert(u2,m3);
    string s4_key2 = marshallBinary(am->getKey(s4));
    string m3_key2 = marshallBinary(am->getKey(m3));
    record(tc, s4_key1.compare(s4_key2) == 0, test+"s4 key does not match");
    record(tc, m3_key1.compare(m3_key2) == 0, test+"m3 key does not match");
    am->removePsswd(bob);
    record(tc, (am->getKey(s4)).length() == 0, test+"s4 key is available when bob is logged off");
    record(tc, (am->getKey(m3)).length() == 0, test+"m3 key is available when bob is logged off");
    am->insertPsswd(bob,secretB);
    string s4_key3 = marshallBinary(am->getKey(s4));
    string m3_key3 = marshallBinary(am->getKey(m3));
    record(tc, s4_key1.compare(s4_key3) == 0, test+"s4 key does not match 1v3");
    record(tc, m3_key1.compare(m3_key3) == 0, test+"m3 key does not match 1v3"); 
    
    am->insert(m4,s6);
    record(tc, (am->getKey(m4)).length() > 0, test+"m4 key does not exist as orphan");
    record(tc, (am->getKey(s6)).length() > 0, test+"s6 key does not exist as orphan AND as accessible by bob");
    string m4_key1 = marshallBinary(am->getKey(m4));
    string s6_key4 = marshallBinary(am->getKey(s6));
    record(tc, s6_key1.compare(s6_key4) == 0, test+"s6 key does not match 1v4");
    am->removePsswd(bob);
    record(tc, (am->getKey(m4)).length() > 0, test+"m4 key does not exist as orphan");
    record(tc, (am->getKey(s6)).length() > 0, test+"s6 key does not exist a child of an orphan");
    string m4_key2 = marshallBinary(am->getKey(m4));
    string s6_key5 = marshallBinary(am->getKey(s6));
    record(tc, s6_key1.compare(s6_key5) == 0, test+"s6 key does not match 1v5");
    record(tc, m4_key1.compare(m4_key2) == 0, test+"m4 key does not match 1v2");


    am->insert(m5,s5);
    am->insert(m5,s7);
    string m5_key = am->getKey(m5);
    string s5_key = am->getKey(s5);
    string s7_key = am->getKey(s7);
    record(tc, m5_key.length() > 0, "message 5 key (orphan) not available");
    record(tc, s5_key.length() > 0, "subject 5 key (orphan) not available");
    record(tc, s7_key.length() > 0, "subject 7 key (orphan) not available");
    string m5_key1 = marshallBinary(m5_key);
    string s5_key1 = marshallBinary(s5_key);
    string s7_key1 = marshallBinary(s7_key);
    am->insert(u1,m5);
    m5_key = am->getKey(m5);
    s5_key = am->getKey(s5);
    s7_key = am->getKey(s7);
    assert_s((am->getKey(alice)).length() == 0, "alice is not logged off");
    record(tc, m5_key.length() == 0, test+"message 5 key available with alice not logged on");
    record(tc, s5_key.length() == 0, test+"subject 5 key available with alice not logged on");
    record(tc, s7_key.length() == 0, test+"subject 7 key available with alice not logged on");
    am->insertPsswd(alice,secretA);
    m5_key = am->getKey(m5);
    s5_key = am->getKey(s5);
    s7_key = am->getKey(s7);
    string m5_key2 = marshallBinary(m5_key);
    string s5_key2 = marshallBinary(s5_key);
    string s7_key2 = marshallBinary(s7_key);
    record(tc, m5_key.length() > 0, test+"message 5 key not available with alice logged on");
    record(tc, m5_key1.compare(m5_key2) == 0, "message 5 key is different");
    record(tc, s5_key.length() > 0, test+"subject 5 key not available with alice logged on");
    record(tc, s5_key1.compare(s5_key2) == 0, "subject 5 key is different");
    record(tc, s7_key.length() > 0, test+"subject 7 key not available with alice logged on");
    record(tc, s7_key1.compare(s7_key2) == 0, "subject 7 key is different");


    am->insert(u3,m15);
    string m15_key = am->getKey(m15);
    record(tc, m15_key.length() > 0, test+"cannot access message 15 key (orphan)");
    string m15_key1 = marshallBinary(m15_key);
    string u3_key = am->getKey(u3);
    record(tc, u3_key.length() > 0, test+"cannot access user 3 key (orphan)");
    string u3_key1 = marshallBinary(u3_key);
    am->insert(m15, s24);
    string s24_key = am->getKey(s24);
    record(tc, s24_key.length() > 0, test+"cannot access subject 24 key (orphan)");
    string s24_key1 = marshallBinary(s24_key);
    am->insertPsswd(chris, secretC);
    string chris_key = am->getKey(chris);
    record(tc, chris_key.length() > 0, test+"cannot access chris key with chris logged on");
    string chris_key1 = marshallBinary(chris_key);
    am->insert(chris, u3);
    chris_key = am->getKey(chris);
    record(tc, chris_key.length() > 0, test+"cannot access chris key after chris->u3 insert");
    string chris_key2 = marshallBinary(chris_key);
    record(tc, chris_key1.compare(chris_key2) == 0,
             test+"chris key is different for orphan and chris logged on");

    am->removePsswd(chris);
    record(tc, (am->getKey(chris)).length() == 0, test+"can access chris key with chris offline");
    record(tc, (am->getKey(u3)).length() == 0, test+"can access user 3 key with chris offline");
    record(tc, (am->getKey(m15)).length() == 0, test+"can access message 15 key with chris offline");
    record(tc, (am->getKey(s24)).length() == 0, test+"can access subject 24 key with chris offline");

    //L3161


}

void
TestAccessManager::run(const TestConfig &tc, int argc, char ** argv)
{
  cerr << "testing meta locally..." << endl;
  testMeta_native(tc, new Connect(tc.host, tc.user, tc.pass, tc.db));

  KeyAccess * ka;
  ka = buildTest(new Connect(tc.host, tc.user, tc.pass, tc.db));

  cerr << "testing meta section of KeyAccess..." << endl;
  testMeta(tc, ka);

  cerr << "single user tests..." << endl;
  testSingleUser(tc, ka);

  delete ka;
  ka = buildTest(new Connect("localhost","root","letmein","cryptdbtest"));
  cerr << "multi user tests..." << endl;
  testMultiBasic(tc, ka);

  delete ka;
  ka = buildTest(new Connect("localhost","root","letmein","cryptdbtest"));
  cerr << "acyclic graphs (not a tree) tests..." << endl;
  testNonTree(tc, ka);

  ka->~KeyAccess();
  ka = buildTest(new Connect("localhost","root","letmein","cryptdbtest"));
  cerr << "orphan tests..." << endl;
  testOrphans(tc, ka);

  cerr << "RESULT: " << npass << "/" << ntest << " passed" << endl;

  delete ka;
}
  
