#include <sstream>
#include <assert.h>
#include <lua5.1/lua.hpp>

#include "EDBProxy.h"
#include "cryptdb_log.h"

class WrapperState {
 public:

    string last_query;

    WrapperState() {
    }

    ~WrapperState() {
    }
};

static EDBProxy * cl = NULL;

static map<string, WrapperState*> clients;

static int
connect(lua_State *L)
{
    string client = luaL_checkstring(L, 1);
    string server = luaL_checkstring(L, 2);
    uint port = luaL_checkint(L, 3);
    string user = luaL_checkstring(L, 4);
    string psswd = luaL_checkstring(L, 5);
    string dbname = luaL_checkstring(L, 6);

    cerr << "~~" << endl;

    cryptdb_logger::setConf(string(getenv("CRYPTDB_LOG")));

    cerr << "env varibales" << endl;

    LOG(wrapper) << "connect " << client << "; "
                 << "server = " << server << ":" << port << "; "
                 << "user = " << user << "; "
                 << "password = " << psswd << "; "
                 << "database = " << dbname;

    WrapperState *ws = new WrapperState();

    string mode = getenv("CRYPTDB_MODE");

    if (!cl) {
        if (mode.compare("single") == 0) {
            cl = new EDBProxy(server, user, psswd, dbname, port, false);
        } else if (mode.compare("multi") == 0) {
            cl = new EDBProxy(server, user, psswd, dbname, port, true);
        } else {
            cl = new EDBProxy(server, user, psswd, dbname, port);
        }
    }

    uint64_t mkey = 113341234;  // XXX
    cl->setMasterKey(BytesFromInt(mkey, AES_KEY_BYTES));

    if (clients.find(client) != clients.end())
        LOG(warn) << "duplicate client entry";
    clients[client] = ws;
    return 0;
}

static int
disconnect(lua_State *L)
{
    string client = luaL_checkstring(L, 1);
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
    string client = luaL_checkstring(L, 1);
    if (clients.find(client) == clients.end())
        return 0;

    string query = luaL_checkstring(L, 2);

    list<string> new_queries;
    try {
        new_queries = cl->rewriteEncryptQuery(query);
    } catch (CryptDBError &e) {
        LOG(wrapper) << "cannot rewrite " << query << ": " << e.msg;
        lua_pushnil(L);
        return 1;
    }

    lua_createtable(L, (int) new_queries.size(), 0);
    int top = lua_gettop(L);
    int index = 1;
    for (auto it = new_queries.begin(); it != new_queries.end(); it++) {
        lua_pushstring(L, it->c_str());
        lua_rawseti(L, top, index);
        index++;
    }

    clients[client]->last_query = query;
    return 1;
}

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
decrypt(lua_State *L)
{
    string client = luaL_checkstring(L, 1);
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

        vector<SqlItem> row;
        lua_pushnil(L);
        while (lua_next(L, -2)) {
            string data = xlua_tolstring(L, -1);
            SqlItem item;
            if (data != "__cryptdb_NULL") {
                item.null = false;
                item.type = MYSQL_TYPE_BLOB;    /* XXX */
                item.data = data;
            } else {
                item.null = true;
            }
            row.push_back(item);
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
            xlua_pushlstring(L, rd.rows[i][j].data);    /* XXX type, null */
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
