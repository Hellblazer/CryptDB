#include "EDBClient.h"
#include <lua5.1/lua.hpp>

EDBClient * cl;
bool initialized = false;
map<string, vector<string> > sensitive;
int sensitive_size = 0;
map<string, int> auto_inc;
int auto_inc_size = 0;

static int init(lua_State *L) {
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
    cerr << "server = " << server << "; user = " << user << "; password = " << psswd << "; database name = " << dbname << endl;
  }
  uint64_t mkey = 113341234;
  string masterKey = BytesFromInt(mkey, AES_KEY_BYTES);
  cl = new EDBClient(server, user, psswd, dbname, masterKey);
  cl->VERBOSE = VERBOSE_G;
  initialized = true;
  return 0;
}

list<const char*> rewrite(string query) {
  cerr << "rewriting..." << endl;
  size_t hasaccess = query.find("hasaccessto");
  size_t equals = query.find("equals");
  if (hasaccess != string::npos) {
    query.replace(hasaccess,17,"");
  }
  if (equals != string::npos) {
    query.replace(equals,11,"");
  }
  
  list<const char*> res;
  res.push_back("INSERT INTO t1 VALUES (1,'one');");
  res.push_back(getCStr(query));
  return res;
}

static int pass_queries(lua_State *L) {
  string query = luaL_checkstring(L,1);
  int insert_id = luaL_checknumber(L,2);
  //rb may contain a new autoinc id
  AutoInc ai;
  ai.incvalue = insert_id;
  cerr << insert_id << endl;
  list<const char*> new_queries;
  new_queries = cl->rewriteEncryptQuery(getCStr(query), &ai);
  //cerr << "got queries" << endl;
  //todo: fix rewriteEncryptQuery so that this is unnecessary
  if(new_queries.size() > 0) {
    cerr << "in wrapper: got first query " << new_queries.front() << "\n";
  } else {
    cerr << "in wrapper: no queries back" << endl;
  }
  lua_createtable(L, new_queries.size(), 0);
  int top = lua_gettop(L);
  int index = 1;
  auto it = new_queries.begin();
  while(it != new_queries.end()) {
    lua_pushstring(L, (*it));
    lua_rawseti(L,top,index);
    it++;
    index++;
  }
  return 1;
}

static int edit_auto(lua_State* L) {
  string table_name = luaL_checkstring(L,1);
  int new_value = luaL_checknumber(L,2);
  auto_inc[table_name] = new_value;
  auto_inc_size = 2*auto_inc.size();
  return 0;
}

static int add_to_map(lua_State* L) {
  string table = luaL_checkstring(L,1);
  vector<string> fields;
  lua_pushnil(L);
  while(lua_next(L,-2) != 0) {
    fields.push_back(luaL_checkstring(L,-1));
    if (VERBOSE_G) {
      cerr << luaL_checkstring(L,-1) << endl;
    }
    lua_pop(L,1);
  }
  sensitive_size += fields.size() + 1;
  sensitive[table] = fields;
  return 0;
}


static int get_map_tables(lua_State *L) {
  if (sensitive.size() == 0) {
    if (VERBOSE_G) {
      cerr << "got nothing in sensitive" << endl;
    }
    return 0;
  }
  if (!lua_checkstack(L, sensitive_size)) {
    assert_s(false, "lua cannot grow stack");
  }
  for (auto outer = sensitive.begin(); outer != sensitive.end(); outer++) {
    lua_pushstring(L, getCStr(outer->first));
  }
  return sensitive.size();
}

static int get_auto_names(lua_State *L) {
  if (auto_inc.size() == 0) {
    if (VERBOSE_G) {
      cerr << "got nothing in auto_inc" << endl;
    }
    return 0;
  }
  if (!lua_checkstack(L, auto_inc_size)) {
    assert_s(false, "lua cannot grow stack");
  }
  for (auto it = auto_inc.begin(); it != auto_inc.end(); it++) {
    lua_pushstring(L, getCStr(it->first));
  }
  return auto_inc.size();
}  

static int get_auto_numbers(lua_State *L) {
  if (auto_inc.size() == 0) {
    if (VERBOSE_G) {
      cerr << "got nothing in auto_inc" << endl;
    }
    return 0;
  }
  if (!lua_checkstack(L, auto_inc_size)) {
    assert_s(false, "lua cannot grow stack");
  }
  for (auto it = auto_inc.begin(); it != auto_inc.end(); it++) {
    lua_pushnumber(L, it->second);
  }
  return auto_inc.size();
}

static int get_map_fields(lua_State *L) {
  int top, index;
  if (sensitive.size() == 0) {
    if (VERBOSE_G) {
      cerr << "got nothing in sensitive" << endl;
    }
    return 0;
  }
  if (!lua_checkstack(L, sensitive_size)) {
    assert_s(false, "lua cannot grow stack");
  }
  for (auto outer = sensitive.begin(); outer != sensitive.end(); outer++) {
    lua_createtable(L, outer->second.size(), 0);
    top = lua_gettop(L);
    index = 1;
    auto inner = outer->second.begin();
    while(inner != outer->second.end()) {
      lua_pushstring(L, getCStr(*inner));
      lua_rawseti(L,top,index);
      ++inner;
      ++index;
    }
  }
  return sensitive.size();
}


class ResultSet {
public:
  string query;
  bool decrypted;
  std::vector< std::vector<std::string> > set;
  std::vector<std::string> field_names;
  std::vector<std::string> working_row;
  ResultSet(string q);
  void append_field(std::string field);
  void append_working(std::string placeholder);
  void end_row();
  void decrypt();
  void PrettyPrint();
};
ResultSet::ResultSet(string q) {
  decrypted = false;
  query = q;
}
void ResultSet::append_field(std::string field) {
  field_names.push_back(field);
}
void ResultSet::append_working(std::string placeholder) {
  cerr << "appending " << placeholder << " to working" << endl;
  working_row.push_back(placeholder);
}
void ResultSet::decrypt() {
  //PrettyPrint();
  vector <vector< string> > *cresultset = &set;
  cresultset->insert(cresultset->begin(),field_names);
  //todo: is returning an empty vector
  cerr << "------>to decryptResults" << endl;
  cerr << query << endl;
  cresultset = cl->decryptResults(getCStr(query), cresultset);
  if (cresultset->size() != 0) {
    field_names = *(cresultset->begin());
    cresultset->erase(cresultset->begin());
    set = (*cresultset);
  }
  else {
    cout << "empty result set" << endl;
  }
}
void ResultSet::end_row() {
  if (!working_row.empty()) {
    cerr << "finishing row" << endl;
    set.push_back(working_row);
  }
  working_row.clear();
}
void ResultSet::PrettyPrint() {
  for(auto f = field_names.begin(); f != field_names.end(); f++) {
    std::cout << *f << " ";
  }
  printf("\n--------\n");
  for(auto outer = set.begin(); outer != set.end(); outer++) {
    for(auto inner = (*outer).begin(); inner != (*outer).end(); inner++) {
      std::cout << *inner << " ";
    }
    std::cout << std::endl;
  }
}

ResultSet *R;

static int new_res(lua_State *L) {
  string query = luaL_checkstring(L,1);
  R = new ResultSet(query);
  return 0;
}

static int populate_fields(lua_State *L) {
  lua_pushnil(L);
  while(lua_next(L, -2) != 0)
    {
      if(lua_isstring(L,-1) && lua_isstring(L,-2)) {
	std::string temp = lua_tostring(L,-2);
	if(!temp.compare("name")) {
	  R->append_field(lua_tostring(L,-1));
	}
      }
      else if(lua_istable(L,-1)) {
	populate_fields(L);
      }
      lua_pop(L, 1);
    }
  return 0;
}

static int populate_rows(lua_State *L) {
  cerr << "in c, populating rows" << endl;
  lua_pushnil(L);
  while(lua_next(L, -2) != 0)
  {
    if(lua_isstring(L,-1)) {
      R->append_working(lua_tostring(L,-1));
    }
    else if(lua_istable(L,-1)) {
      populate_rows(L);
      R->end_row();
    }
    lua_pop(L, 1);
  }
  R->end_row();
  return 0;
}

static int decrypt(lua_State *L) {
  R->decrypt();
  cerr << "decrypted" << endl;
  return 0;
}

static int print_res(lua_State *L) {
  R->PrettyPrint();
  return 0;
}

static int get_fields(lua_State *L) {
  lua_createtable(L, R->field_names.size(), 0);
  int top = lua_gettop(L);
  int index = 1;
  auto it = R->field_names.begin();
  while(it != R->field_names.end()) {
    lua_pushstring(L, (*it).c_str());
    lua_rawseti(L,top,index);
    ++it;
    ++index;
  }
  return 1;
}
static int get_rows(lua_State *L) {
  int top, index;
  for(auto outer = R->set.begin(); outer != R->set.end(); outer++) {
    lua_createtable(L, (*outer).size(), 0);
    top = lua_gettop(L);
    index = 1;
    auto inner = (*outer).begin();
    while(inner != (*outer).end()) {
      lua_pushstring(L, (*inner).c_str());
      lua_rawseti(L,top,index);
      ++inner;
      ++index;
    }
  }
  //R->decrypted = false;
  //cerr << R->set.size() << endl;
  //R->PrettyPrint();
  return R->set.size();
}
  
static const struct luaL_reg resultsetlib[] =
  {
    {"init",init},
    {"pass_query",pass_queries},
    {"edit_auto",edit_auto},
    {"add_to_map",add_to_map},
    {"get_auto_names",get_auto_names},
    {"get_auto_numbers",get_auto_numbers},
    {"get_map_names",get_map_tables},
    {"get_map_fields",get_map_fields},
    {"new_res",new_res},
    {"fields",populate_fields},
    {"rows",populate_rows},
    {"print",print_res},
    {"get_fields",get_fields},
    {"get_rows",get_rows},
    {"decrypt",decrypt},
    {NULL,NULL}
  };

extern "C" int luaopen_resultset (lua_State *L)
{
  luaL_openlib(L,"CryptDB",resultsetlib,0);
  return 1;
}
