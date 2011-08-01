#include <sstream>
#include "EDBClient.h"
#include "cryptdb_log.h"
#include <lua5.1/lua.hpp>

static EDBClient *lua_cl;
static bool initialized = false;
static string last_query;   // XXX

static int
init(lua_State *L)
{
    if (initialized) {
        if (VERBOSE_G) {
            cerr << "already have connection" << endl;
        }
    }

    string server = luaL_checkstring(L,1);
    string user = luaL_checkstring(L,2);
    string psswd = luaL_checkstring(L,3);
    string dbname = luaL_checkstring(L,4);
    if (VERBOSE_G) {
        cerr << "server = " << server << "; user = " << user <<
        "; password = " << psswd << "; database name = " << dbname << endl;
    }

    uint64_t mkey = 113341234;
    lua_cl = new EDBClient(server, user, psswd, dbname);
    lua_cl->setMasterKey(BytesFromInt(mkey, AES_KEY_BYTES));
    lua_cl->VERBOSE = VERBOSE_G;
    initialized = true;

    cryptdb_logger::enable(log_group::log_wrapper);

    return 0;
}

static int
rewrite(lua_State *L)
{
    string query = luaL_checkstring(L,1);

    AutoInc ai;
    ai.incvalue = 999;  // XXX?!
    list<string> new_queries;
    try {
        new_queries = lua_cl->rewriteEncryptQuery(query, &ai);
    } catch (CryptDBError &e) {
        LOG(wrapper) << "cannot rewrite " << query << ": " << e.msg;
    }

    lua_createtable(L, (int) new_queries.size(), 0);
    int top = lua_gettop(L);
    int index = 1;
    for (auto it = new_queries.begin(); it != new_queries.end(); it++) {
        lua_pushstring(L, it->c_str());
        lua_rawseti(L, top, index);
        index++;
    }

    last_query = query;

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
    ResType r;

    /* iterate over the fields argument */
    lua_pushnil(L);
    while (lua_next(L, 1)) {
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
    while (lua_next(L, 2)) {
        if (!lua_istable(L, -1))
            LOG(warn) << "mismatch";

        vector<string> row;
        lua_pushnil(L);
        while (lua_next(L, -2)) {
            row.push_back(xlua_tolstring(L, -1));
            lua_pop(L, 1);
        }

        r.rows.push_back(row);
        lua_pop(L, 1);
    }

    /*
     * the marshalling plan is a mess, but let's try to
     * write adapters here for it anyway..
     */
    for (uint i = 0; i < r.types.size(); i++) {
        if (r.types[i] != MYSQL_TYPE_VAR_STRING &&
            r.types[i] != MYSQL_TYPE_BLOB)
            continue;

        for (uint j = 0; j < r.rows.size(); j++)
            r.rows[j][i] = marshallBinary(r.rows[j][i]);
    }

    ResType rd = lua_cl->decryptResults(last_query, r);

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
            xlua_pushlstring(L, rd.rows[i][j]);
            lua_settable(L, t_row);
        }

        lua_settable(L, t_rows);
    }

    return 2;
}

static const struct luaL_reg
cryptdb_lib[] = {
#define F(n) { #n, n }
    F(init),
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
