#include <sstream>
#include <fstream>
#include <assert.h>
#include <lua5.1/lua.hpp>

#include <util/ctr.hh>
#include <util/cryptdb_log.hh>
#include <util/scoped_lock.hh>

#include <edb/EDBProxy.hh>


using namespace std;

class WrapperState {
 public:
    string last_query;
    bool considered;
    ofstream * PLAIN_LOG;
};

static Timer t;

static EDBProxy * cl = NULL;
static pthread_mutex_t big_lock;

static bool DO_CRYPT = true;

static bool EXECUTE_QUERIES = true;

static string TRAIN_QUERY ="";

static bool LOG_PLAIN_QUERIES = false;
static string PLAIN_BASELOG = "";


static int counter = 0;

static map<string, WrapperState*> clients;

static string
xlua_tolstring(lua_State *l, int index)
{
    size_t len;
    const char *s = lua_tolstring(l, index, &len);
    return string(s, len);
}

static void
xlua_pushlstring(lua_State *l, const string &s)
{
    lua_pushlstring(l, s.data(), s.length());
}

static int
connect(lua_State *L)
{
    
    ANON_REGION(__func__, &perf_cg);
    scoped_lock l(&big_lock);

    

    string client = xlua_tolstring(L, 1);
    string server = xlua_tolstring(L, 2);
    uint port = luaL_checkint(L, 3);
    string user = xlua_tolstring(L, 4);
    string psswd = xlua_tolstring(L, 5);
    string dbname = xlua_tolstring(L, 6);

    WrapperState *ws = new WrapperState();

    if (clients.find(client) != clients.end()) {
           LOG(warn) << "duplicate client entry";
    }

    clients[client] = ws;

    if (!cl) {
      cerr << "starting proxy\n";
        cryptdb_logger::setConf(string(getenv("CRYPTDB_LOG")?:""));

        LOG(wrapper) << "connect " << client << "; "
                     << "server = " << server << ":" << port << "; "
                     << "user = " << user << "; "
                     << "password = " << psswd << "; "
                     << "database = " << dbname;

        string mode = getenv("CRYPTDB_MODE")?:"";
        if (mode == "single") {
            cl = new EDBProxy(server, user, psswd, dbname, port, false);
        } else if (mode == "multi") {
            cl = new EDBProxy(server, user, psswd, dbname, port, true);
        } else {
            cl = new EDBProxy(server, user, psswd, dbname, port);
        }

        uint64_t mkey = 113341234;  // XXX do not change as it's used for tpcc exps
        cl->setMasterKey(BytesFromInt(mkey, AES_KEY_BYTES));

        //may need to do training
        char * ev = getenv("TRAIN_QUERY");
        if (ev) {
            string trainQuery = ev;
            LOG(wrapper) << "proxy trains using " << trainQuery;
            if (trainQuery != "") {
                bool consider;
                cl->rewriteEncryptQuery(trainQuery, consider);
            } else {
                cerr << "empty training!\n";
            }
        }

        ev = getenv("DO_CRYPT");
        if (ev) {
            string useCryptDB = string(ev);
            if (useCryptDB == "false") {
                LOG(wrapper) << "do not crypt queries/results";
                DO_CRYPT = false;
            } else {
                LOG(wrapper) << "crypt queries/result";
            }
        }


        ev = getenv("EXECUTE_QUERIES");
        if (ev) {
            string execQueries = string(ev);
            if (execQueries == "false") {
                LOG(wrapper) << "do not execute queries";
                EXECUTE_QUERIES = false;
            } else {
                LOG(wrapper) << "execute queries";
            }
        }

        ev = getenv("LOAD_ENC_TABLES");
        if (ev) {
            cerr << "loading enc tables\n";
            cl->loadEncTables(string(ev));
        }

        ev = getenv("LOG_PLAIN_QUERIES");
        if (ev) {
            string logPlainQueries = string(ev);
            if (logPlainQueries != "") {
                LOG_PLAIN_QUERIES = true;
                PLAIN_BASELOG = logPlainQueries;
                logPlainQueries += StringFromVal(++counter);

                assert_s(system(("rm -f" + logPlainQueries + "; touch " + logPlainQueries).c_str()) >= 0, "failed to rm -f and touch " + logPlainQueries);

                ofstream * PLAIN_LOG = new ofstream(logPlainQueries, ios_base::app);
                LOG(wrapper) << "proxy logs plain queries at " << logPlainQueries;
                assert_s(PLAIN_LOG != NULL, "could not create file " + logPlainQueries);
                clients[client]->PLAIN_LOG = PLAIN_LOG;
            } else {
                LOG_PLAIN_QUERIES = false;
            }
        }



    } else {
        if (LOG_PLAIN_QUERIES) {
            string logPlainQueries = PLAIN_BASELOG+StringFromVal(++counter);
            assert_s(system((" touch " + logPlainQueries).c_str()) >= 0, "failed to remove or touch plain log");
            LOG(wrapper) << "proxy logs plain queries at " << logPlainQueries;

            ofstream * PLAIN_LOG = new ofstream(logPlainQueries, ios_base::app);
            assert_s(PLAIN_LOG != NULL, "could not create file " + logPlainQueries);
            clients[client]->PLAIN_LOG = PLAIN_LOG;
        }
    }



    return 0;
}

static int
disconnect(lua_State *L)
{
    ANON_REGION(__func__, &perf_cg);
    scoped_lock l(&big_lock);

    string client = xlua_tolstring(L, 1);
    if (clients.find(client) == clients.end())
        return 0;

    LOG(wrapper) << "disconnect " << client;
    delete clients[client];
    clients.erase(client);

    return 0;
}

static int
rewrite(lua_State *L)
{
    ANON_REGION(__func__, &perf_cg);
    scoped_lock l(&big_lock);

    string client = xlua_tolstring(L, 1);
    if (clients.find(client) == clients.end())
        return 0;

    string query = xlua_tolstring(L, 2);

    clients[client]->considered = true;

    list<string> new_queries;

    t.lap_ms();
    if (EXECUTE_QUERIES) {
        if (!DO_CRYPT) {
            new_queries.push_back(query);
        } else {
            try {
                new_queries = cl->rewriteEncryptQuery(query, clients[client]->considered);
                //cerr << "query: " << *new_queries.begin() << " considered ? " << clients[client]->considered << "\n";
            } catch (CryptDBError &e) {
                LOG(wrapper) << "cannot rewrite " << query << ": " << e.msg;
                lua_pushnil(L);
                lua_pushnil(L);
                return 2;
            }
        }
    }

    if (LOG_PLAIN_QUERIES) {
        *(clients[client]->PLAIN_LOG) << query << "\n";
    }

    lua_pushboolean(L, clients[client]->considered);
    //lua_pushboolean(L, true);

    lua_createtable(L, (int) new_queries.size(), 0);
    int top = lua_gettop(L);
    int index = 1;
    for (auto it = new_queries.begin(); it != new_queries.end(); it++) {
        xlua_pushlstring(L, *it);
        lua_rawseti(L, top, index);
        index++;
    }

    clients[client]->last_query = query;
    return 2;
}

static int
decrypt(lua_State *L)
{
    ANON_REGION(__func__, &perf_cg);
    scoped_lock l(&big_lock);

    string client = xlua_tolstring(L, 1);
    if (clients.find(client) == clients.end())
        return 0;

    ResType r;

    /* iterate over the fields argument */
    lua_pushnil(L);
    while (lua_next(L, 2)) {
        if (!lua_istable(L, -1))
            LOG(warn) << "mismatch";

        lua_pushnil(L);
        while (lua_next(L, -2)) {
            string k = xlua_tolstring(L, -2);
            if (k == "name")
                r.names.push_back(xlua_tolstring(L, -1));
            else if (k == "type")
                r.types.push_back((enum_field_types) luaL_checkint(L, -1));
            else
                LOG(warn) << "unknown key " << k;
            lua_pop(L, 1);
        }

        lua_pop(L, 1);
    }

    /* iterate over the rows argument */
    lua_pushnil(L);
    while (lua_next(L, 3)) {
        if (!lua_istable(L, -1))
            LOG(warn) << "mismatch";

        /* initialize all items to NULL, since Lua skips nil array entries */
        vector<SqlItem> row(r.names.size());

        lua_pushnil(L);
        while (lua_next(L, -2)) {
            int key = luaL_checkint(L, -2);
            string data = xlua_tolstring(L, -1);
            row[key - 1].null = false;
            row[key - 1].type = MYSQL_TYPE_BLOB;    /* XXX */
            row[key - 1].data = data;
            lua_pop(L, 1);
        }

        r.rows.push_back(row);
        lua_pop(L, 1);
    }

    ResType rd;
    if (!DO_CRYPT || !clients[client]->considered) {
        rd = r;
    } else {
        try {
            rd = cl->decryptResults(clients[client]->last_query, r);
        }
        catch(CryptDBError e) {
            lua_pushnil(L);
            lua_pushnil(L);
            return 2;
        }
    }

    /* return decrypted result set */
    lua_createtable(L, (int) rd.names.size(), 0);
    int t_fields = lua_gettop(L);
    for (uint i = 0; i < rd.names.size(); i++) {
        lua_createtable(L, 0, 2);
        int t_field = lua_gettop(L);

        /* set name for field */
        xlua_pushlstring(L, rd.names[i]);
        lua_setfield(L, t_field, "name");

        /* set type for field */
        lua_pushinteger(L, rd.types[i]);
        lua_setfield(L, t_field, "type");

        /* insert field element into fields table at i+1 */
        lua_rawseti(L, t_fields, i+1);
    }

    lua_createtable(L, (int) rd.rows.size(), 0);
    int t_rows = lua_gettop(L);
    for (uint i = 0; i < rd.rows.size(); i++) {
        lua_createtable(L, (int) rd.rows[i].size(), 0);
        int t_row = lua_gettop(L);

        for (uint j = 0; j < rd.rows[i].size(); j++) {
            if (rd.rows[i][j].null) {
                lua_pushnil(L);
            } else {
                xlua_pushlstring(L, rd.rows[i][j].data);
            }
            lua_rawseti(L, t_row, j+1);
        }

        lua_rawseti(L, t_rows, i+1);
    }

    //cerr << clients[client]->last_query << " took (too long) " << t.lap_ms() << endl;;
    return 2;
}

static const struct luaL_reg
cryptdb_lib[] = {
#define F(n) { #n, n }
    F(connect),
    F(disconnect),
    F(rewrite),
    F(decrypt),
    { 0, 0 },
};

extern "C" int lua_cryptdb_init(lua_State *L);

int
lua_cryptdb_init(lua_State *L)
{
    luaL_openlib(L, "CryptDB", cryptdb_lib, 0);
    return 1;
}
