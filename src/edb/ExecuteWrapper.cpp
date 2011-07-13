#include "EDBClient.h"
#include <lua.hpp>

EDBClient * cl;
bool initialized = false;
map<string, vector<string> > sensitive;
int sensitive_size = 0;

static int init(lua_State *L) {
	if (initialized) {
		if (VERBOSE_G) { cerr << "already have connection" << endl;}
		return 0;
	}
	string server = luaL_checkstring(L,1);
	string user = luaL_checkstring(L,2);
	string psswd = luaL_checkstring(L,3);
	string dbname = luaL_checkstring(L,4);
	if (VERBOSE_G) { cout << "server = " << server << "; user = " << user << "; password = " << psswd << "; dbname = " << dbname << endl;}
	uint64_t mkey = 113341234;
	unsigned char * masterKey = BytesFromInt(mkey, AES_KEY_BYTES);
	cl = new EDBClient(server, user, psswd, dbname, masterKey);
	cl->VERBOSE = VERBOSE_G;
	initialized = true;
	return 0;
}

static int execute(lua_State *L) {
	string query = luaL_checkstring(L,1);
	vector <vector <string> > *resultset = cl->execute(getCStr(query));
	if (VERBOSE_G) { cout << "C INTERFACE SPEAKING" << endl;}
	if (VERBOSE_G) { cout << resultset << endl;}
	if (resultset == 0) {
	  //cerr << "C interface encountered issue \n";
		cerr << "C issue!! \n";
		assert_s(false, "");
		return 0;
	}
	if (resultset->size() == 0) {
	  return 0;
	}
	int size = resultset->size();
	//cerr << size << endl;
	int field_count = resultset->at(0).size();
	//cerr << "growing stack to " << size*field_count << endl;
	if (!lua_checkstack(L, size*field_count)) {
	  assert_s(false,"lua cannot grow stack!");
	}
	vector <vector <string> >::iterator outer;
	int top, index;
	vector<string>::iterator inner;
	int counter = 0;
	for(outer = resultset->begin(); outer != resultset->end(); outer++) {
		lua_createtable(L, outer->size(), 0);
		top = lua_gettop(L);
		index = 1;
		inner = outer->begin();
		while(inner != outer->end()) {
			string val = *inner;
			//cerr << "length of " << val << " is " << val.length() << endl;
			char * test = getCStr(val);
			lua_pushstring(L, test);
			lua_rawseti(L,top,index);
			++inner;
			++index;
		}
		counter++;
	}
	//int size = resultset->size();
	resultset->clear();
	//cerr << "size in C is " << size << endl;
	return size;
}

static int add_to_map(lua_State* L) {
	string table = luaL_checkstring(L,1);
	//cout << table << endl;
	vector<string> fields;
	lua_pushnil(L);
	while(lua_next(L,-2) != 0)
	{
		fields.push_back(luaL_checkstring(L,-1));
		if (VERBOSE_G) { cout << luaL_checkstring(L,-1) << endl;}
		lua_pop(L,1);
	}
	sensitive_size += fields.size() + 1;
	sensitive[table] = fields;
	return 0;
}

static int get_map_tables(lua_State *L) {
	map<string, vector <string> >::iterator outer;
	//cerr << "sensitive size " << sensitive.size() << endl;
	if (sensitive.size() == 0) {
		if (VERBOSE_G) { cerr << "got nothing in sensitive" << endl;}
	  return 0;
	}
	//cerr << "growing lua stack to " << sensitive_size << endl;
	if (!lua_checkstack(L, sensitive_size)) {
	  assert_s(false,"lua cannot grow stack!");
	}
	for(outer = sensitive.begin(); outer != sensitive.end(); outer++) {
	  lua_pushstring(L, getCStr(outer->first));
	}
	return sensitive.size();
}

static int get_map_fields(lua_State *L) {
	map<string, vector <string> >::iterator outer;
	int top, index;
	vector<string>::iterator inner;
	//cerr << "sensitive " << sensitive.size() << endl;
	if (sensitive.size() == 0) {
		if (VERBOSE_G) { cerr << "got nothing in sensitive" << endl;}
	  return 0;
	}
	//cerr << "growing lua stack to " << sensitive_size << endl;
	if (!lua_checkstack(L, sensitive_size)) {
	  assert_s(false,"lua cannot grow stack!");
	}
	for(outer = sensitive.begin(); outer != sensitive.end(); outer++) {
		lua_createtable(L, outer->second.size(), 0);
		top = lua_gettop(L);
		index = 1;
		inner = outer->second.begin();
		while(inner != outer->second.end()) {
		        lua_pushstring(L, getCStr(*inner));
			lua_rawseti(L,top,index);
			++inner;
			++index;
		}
	}
	return sensitive.size();
}

static const struct luaL_reg resultsetlib[] =
{
		{"init",init},
		{"execute",execute},
		{"add_to_map",add_to_map},
		{"get_map_names",get_map_tables},
		{"get_map_fields",get_map_fields},
		{NULL,NULL}
};

extern "C" int luaopen_resultset (lua_State *L)
{
	luaL_openlib(L,"CryptDB",resultsetlib,0);
	return 1;
}
