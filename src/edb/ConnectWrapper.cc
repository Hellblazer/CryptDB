#include <sstream>
#include <assert.h>
#include <lua5.1/lua.hpp>

#include "EDBProxy.h"
#include "cryptdb_log.h"
#include <fstream>

class WrapperState {
 public:
    string last_query;
};

static EDBProxy * cl = NULL;

static string TRAIN_QUERY ="";


static bool LOG_PLAIN_QUERIES = false;
static ofstream * PLAIN_LOG = NULL;

static bool LOG_ENCRYPT_QUERIES = false;
static ofstream * ENCRYPT_LOG = NULL;

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
    string client = xlua_tolstring(L, 1);
    string server = xlua_tolstring(L, 2);
    uint port = luaL_checkint(L, 3);
    string user = xlua_tolstring(L, 4);
    string psswd = xlua_tolstring(L, 5);
    string dbname = xlua_tolstring(L, 6);

    cryptdb_logger::setConf(string(getenv("CRYPTDB_LOG")));

    LOG(wrapper) << "connect " << client << "; "
                 << "server = " << server << ":" << port << "; "
                 << "user = " << user << "; "
                 << "password = " << psswd << "; "
                 << "database = " << dbname;

    WrapperState *ws = new WrapperState();

    if (!cl) {

        string mode = getenv("CRYPTDB_MODE");
        if (mode == "single") {
            cl = new EDBProxy(server, user, psswd, dbname, port, false);
        } else if (mode == "multi") {
            cl = new EDBProxy(server, user, psswd, dbname, port, true);
        } else {
            cl = new EDBProxy(server, user, psswd, dbname, port);
        }

        //may need to do training
        char * ev = getenv("TRAIN_QUERY");
        if (ev) {
            string trainQuery = ev;
            LOG(wrapper) << "proxy trains using " << ev;
            if (trainQuery != "") {
                cl->execute(trainQuery);
            }
        }

        ev = getenv("LOG_PLAIN_QUERIES");
        if (ev) {
            string logPlainQueries = string(ev);
            if (logPlainQueries != "") {
                LOG_PLAIN_QUERIES = true;
                int res = system(("rm -f" + logPlainQueries + "; touch " + logPlainQueries).c_str());
                assert_s(res >= 0, "failed to rm -f and touch " + logPlainQueries);
                PLAIN_LOG = new ofstream(logPlainQueries, ios_base::app);
                LOG(wrapper) << "proxy logs plain queries at " << logPlainQueries;
                assert_s(PLAIN_LOG != NULL, "could not create file " + logPlainQueries);
            } else {
                LOG_PLAIN_QUERIES = false;
            }
        }

        ev = getenv("LOG_ENCRYPT_QUERIES");
        if (ev) {
            string logEncryptQueries = string(ev);
            if (logEncryptQueries != "") {
                LOG_ENCRYPT_QUERIES = true;
                LOG(wrapper) << "proxy logs encrypted queries ";
                ENCRYPT_LOG = new ofstream(logEncryptQueries, ios_base::app);
                assert_s(ENCRYPT_LOG != NULL, "could not create file " + logEncryptQueries);
            } else {
                LOG_ENCRYPT_QUERIES = false;
            }
        }



    }

    uint64_t mkey = 113341234;  // XXX do not change as it's used for tpcc exps
    cl->setMasterKey(BytesFromInt(mkey, AES_KEY_BYTES));

    if (clients.find(client) != clients.end())
        LOG(warn) << "duplicate client entry";
    clients[client] = ws;
    return 0;
}

static int
disconnect(lua_State *L)
{
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
    string client = xlua_tolstring(L, 1);
    if (clients.find(client) == clients.end())
        return 0;

    string query = xlua_tolstring(L, 2);

    list<string> new_queries;
    try {
        new_queries = cl->rewriteEncryptQuery(query);
    } catch (CryptDBError &e) {
        LOG(wrapper) << "cannot rewrite " << query << ": " << e.msg;
        lua_pushnil(L);
        return 1;
    }

    if (LOG_PLAIN_QUERIES) {
        *PLAIN_LOG << query << "\n";
    }

    if (LOG_ENCRYPT_QUERIES) {
        for (auto it = new_queries.begin(); it != new_queries.end(); it++) {
            *ENCRYPT_LOG << *it << "\n";
        }
    }


    lua_createtable(L, (int) new_queries.size(), 0);
    int top = lua_gettop(L);
    int index = 1;
    for (auto it = new_queries.begin(); it != new_queries.end(); it++) {
        xlua_pushlstring(L, *it);
        lua_rawseti(L, top, index);
        index++;

    }

    clients[client]->last_query = query;
    return 1;
}

static int
decrypt(lua_State *L)
{
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
    try {
        rd = cl->decryptResults(clients[client]->last_query, r);
    }
    catch(CryptDBError e) {
        lua_pushnil(L);
        lua_pushnil(L);
        return 2;
    }

    /* return decrypted result set */
    lua_newtable(L);
    int t_fields = lua_gettop(L);
    for (uint i = 0; i < rd.names.size(); i++) {
        /* pre-configure stack for inserting field into fields table at i+1 */
        lua_pushinteger(L, i+1);
        lua_newtable(L);
        int t_field = lua_gettop(L);

        /* set name for field */
        xlua_pushlstring(L, "name");
        xlua_pushlstring(L, rd.names[i]);
        lua_settable(L, t_field);

        /* set type for field */
        xlua_pushlstring(L, "type");
        lua_pushinteger(L, rd.types[i]);
        lua_settable(L, t_field);

        /* insert field element into fields table */
        lua_settable(L, t_fields);
    }

    lua_newtable(L);
    int t_rows = lua_gettop(L);
    for (uint i = 0; i < rd.rows.size(); i++) {
        /* pre-configure stack for inserting row table */
        lua_pushinteger(L, i+1);
        lua_newtable(L);
        int t_row = lua_gettop(L);

        for (uint j = 0; j < rd.rows[i].size(); j++) {
            lua_pushinteger(L, j+1);
            if (rd.rows[i][j].null) {
                lua_pushnil(L);
            } else {
                xlua_pushlstring(L, rd.rows[i][j].data);
            }
            lua_settable(L, t_row);
        }

        lua_settable(L, t_rows);
    }

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
