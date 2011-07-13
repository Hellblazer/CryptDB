#include <iostream>
#include <vector>
#include <string>
#include "../EDBClient.h"
#include <lua.hpp>

class ResultSet {
public:
  std::vector< std::vector<std::string> > set;
  std::vector<std::string> field_names;
  std::vector<std::string> working_row;
  ResultSet() {};
  void append_field(std::string field);
  void append_working(std::string placeholder);
  void end_row();
  void decrypt();
  void PrettyPrint();
};

void ResultSet::append_field(std::string field) {
  field_names.push_back(field);
}
void ResultSet::append_working(std::string placeholder) {
  //int pnum = int(placeholder[placeholder.length()-1])+1;
  //placeholder[placeholder.length()-1] = char(pnum);
  working_row.push_back(placeholder);
}
void RestultSet::decrypt() {
  <vector <vector< string> > *cresultset = &set;
  cresultset->push_front(field_names);
  cresultset = cl->decryptResults(query, resultset);
  field_names = cresultset->at(0);
  cresultset->erase(0);
  set = (*cresultset);
}

void ResultSet::end_row() {
  set.push_back(working_row);
  working_row.clear();
}
void ResultSet::PrettyPrint() {
  std::vector< std::string >::iterator f;
  for(f = field_names.begin(); f != field_names.end(); f++) {
    std::cout << *f << " ";
  }
  printf("\n--------\n");
  std::vector<std::vector< std::string> >::iterator outer;
  for(outer = set.begin(); outer != set.end(); outer++) {
    std::vector< std::string >::iterator inner;
    for(inner = (*outer).begin(); inner != (*outer).end(); inner++) {
      std::cout << *inner << " ";
    }
    std::cout << std::endl;
  }
}

ResultSet *R;

static int new_res(lua_State *L) {
  R = new ResultSet();
  return 0;
}

static int populate_fields(lua_State *L) {
  lua_pushnil(L);
  while(lua_next(L, -2) != 0)
  {
    /*if(lua_isstring(L,-2)) {
      printf("%s\n",lua_tostring(L,-2));
      }*/


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
  lua_pushnil(L);
  while(lua_next(L, -2) != 0)
  { 
    /*printf("%s - %s\n",
	   lua_typename(L, lua_type(L, -2)),
	   lua_typename(L, lua_type(L, -1)));*/
    if(lua_isstring(L,-1)) {
      //printf("%s\n",lua_tostring(L,-1));
      R->append_working(lua_tostring(L,-1));
    }
    else if(lua_istable(L,-1)) {
      populate_rows(L);
      R->end_row();
    }
    lua_pop(L, 1);
  }
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
  std::vector<std::string>::iterator it = R->field_names.begin();
  while(it != R->field_names.end()) {
    lua_pushstring(L, (*it).c_str());
    lua_rawseti(L,top,index);
    ++it;
    ++index;
  }
  return 1;
}


static int get_rows(lua_State *L) {
  std::vector <std::vector <std::string> >::iterator outer;
  int top, index;
  std::vector<std::string>::iterator inner;
  for(outer = R->set.begin(); outer != R->set.end(); outer++) {
    lua_createtable(L, (*outer).size(), 0);  
    top = lua_gettop(L);
    index = 1;
    inner = (*outer).begin();
    while(inner != (*outer).end()) {
      lua_pushstring(L, (*inner).c_str());
      lua_rawseti(L,top,index);
      ++inner;
      ++index;
    }
  }
  return R->set.size();
}

static const struct luaL_reg resultsetlib[] =
  {
    {"init",new_res},
    {"fields",populate_fields},
    {"rows",populate_rows},
    {"print",print_res},
    {"get_fields",get_fields},
    {"get_rows",get_rows},
    {NULL,NULL}
  };

extern "C" int luaopen_resultset (lua_State *L)
{
  luaL_openlib(L,"decrypt",resultsetlib,0);
  return 1;
}


