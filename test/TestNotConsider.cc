/*
 * TestNotConsider
 * -- tests optimization for query passing, specifically that queries with no sensitive
 *    fields are not encrypted
 *
 */

#include <test/TestNotConsider.hh>
#include <util/cryptdb_log.hh>


using namespace std;

static int ntest = 0;
static int npass = 0;

TestNotConsider::TestNotConsider() {
}

TestNotConsider::~TestNotConsider() {
}

vector<Query> CreateSingle = {
    Query("CREATE TABLE msgs (msgid integer PRIMARY KEY AUTO_INCREMENT, msgtext enc text)",true),
    Query("CREATE TABLE privmsg (msgid enc integer, recid enc integer, senderid enc integer)",true),
    Query("CREATE TABLE uncrypt (id integer, t text)",true),
    Query("CREATE TABLE forum (forumid integer AUTO_INCREMENT PRIMARY KEY, title enc text)",true),
    Query("CREATE TABLE post (postid integer AUTO_INCREMENT PRIMARY KEY, forumid enc integer, posttext enc text, author enc integer)",true),
    Query("CREATE TABLE u (userid enc integer, username enc text)",true),
    Query("CREATE TABLE "+PWD_TABLE_PREFIX+"u (username enc text, psswd enc text)",true)
};

vector<Query> CreateMulti = {
    Query("CREATE TABLE msgs (msgid equals privmsg.msgid integer AUTO_INCREMENT PRIMARY KEY , msgtext encfor msgid text)",true),
    Query("CREATE TABLE privmsg (msgid integer, recid equals u.userid speaks_for msgid integer, senderid speaks_for msgid integer)",true),
    Query("CREATE TABLE uncrypt (id integer, t text)",true),
    Query("CREATE TABLE forum (forumid integer AUTO_INCREMENT PRIMARY KEY, title text)",true),
    Query("CREATE TABLE post (postid integer AUTO_INCREMENT PRIMARY KEY, forumid equals forum.forumid integer, posttext encfor forumid text, author equals u.userid speaks_for forumid integer)",true),
    Query("CREATE TABLE u (userid equals privmsg.senderid integer, username givespsswd userid text)",true),
    Query("COMMIT ANNOTATIONS",true)
};

vector<Query> QueryList = {
    Query("INSERT INTO uncrypt VALUES (1, 'first')", false),
    Query("INSERT INTO uncrypt (title) VALUES ('second')", false),
    Query("INSERT INTO msgs VALUES (1, 'texty text text')", true),
    Query("INSERT INTO post (forumid, posttext, author) VALUES (1, 'words', 1)", true),
    Query("INSERT INTO u (1, 'alice')", true),
    Query("INSERT INTO "+PWD_TABLE_PREFIX+"u ('alice', 'secretA')", true),

    Query("SELECT * FROM uncrypt", false),
    Query("SELECT * FROM msgs", true),
    Query("SELECT postid FROM post", true),
    Query("SELECT posttext FROM post", true),
    Query("SELECT recid FROM privmsg WHERE msgid = 1",true),
    Query("SELECT postid FROM post WHERE forumid = 1",true),
    Query("SELECT postid FROM post WHERE posttext LIKE '%ee%'",true),

    Query("SELECT * FROM uncrypt, post", true),
    Query("SELECT postid FROM forum, post WHERE forum.formid = post.forumid",true),
    
    Query("UPDATE uncrypt SET t = 'weeeeeee' WHERE id = 3",false),
    Query("UPDATE privmsg SET msgid = 4",true),

    Query("DELETE FROM uncrypt", false),
    Query("DELETE FROM post WHERE postid = 5", true),
    Query("DELETE FROM "+PWD_TABLE_PREFIX+"u WHERE username='alice'", true)
};

vector<Query> Drop = {
    Query("DROP TABLE msgs", true),
    Query("DROP TABLE privmsg", true),
    Query("DROP TABLE uncrypt", true),
    Query("DROP TABLE forum",true),
    Query("DROP TABLE post",true),
    Query("DROP TABLE u",true)
};

static void
Check(const TestConfig &tc, const vector<Query> &queries, EDBProxy * cl, bool createdrop) {
    //all create queries should go be considered...
    for (auto q = queries.begin(); q != queries.end(); q++) {
        ntest++;
        command com = getCommand(q->query);
        if (cl->considerQuery(com, q->query) == q->test_res) {
            npass++;
        } else {
            LOG(test) << q->query << " had consider " << q->test_res;
            if (tc.stop_if_fail) {
                assert_s(false, "failed!");
            }
        }
    }
    if (!createdrop) {
        return;
    }
    //have to have queries in place to run other tests...
    for (auto q = queries.begin(); q != queries.end(); q++) {
        cl->execute(q->query);
    }
}

static void
Consider(const TestConfig &tc, bool multi) {
    uint64_t mkey = 1144220039;
    string masterKey = BytesFromInt(mkey, AES_KEY_BYTES);
    EDBProxy * cl;
    cl = new EDBProxy(tc.host, tc.user, tc.pass, tc.db, tc.port, multi);
    cl->setMasterKey(masterKey);
    if (multi) {
        Check(tc, CreateMulti, cl, true);
    } else {
        Check(tc, CreateSingle, cl, true);
    }

    Check(tc, QueryList, cl, false);

    Check(tc, Drop, cl, true);

    if (!multi) {
        cl->execute("DROP TABLE "+PWD_TABLE_PREFIX+"u");
    }
}

void
TestNotConsider::run(const TestConfig &tc, int argc, char ** argv) {
    //only works on multi-princ, so as not to mess up TCP benchmarking
    Consider(tc, true);

    cerr << "RESULT: " << npass << "/" << ntest << endl;
}
