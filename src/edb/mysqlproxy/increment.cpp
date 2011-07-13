#include <iostream>
#include <string>
#include <lua.hpp>

static int incr(lua_State* L) {
  std::string input = luaL_checkstring(L,1);
  int num = int(input[input.length()-1])+1;
  input[input.length()-1] = char(num);
  lua_pushstring(L,input.c_str());
  return 1;
}

static int decr(lua_State* L) {
  std::string input = luaL_checkstring(L,1);
  int num = int(input[input.length()-1])-1;
  input[input.length()-1] = char(num);
  lua_pushstring(L,input.c_str());
  return 1;
}

static const struct luaL_reg testinc[] = 
  {
    {"incr", incr},
    {"decr", decr},
    {NULL, NULL}
  };

extern "C" int luaopen_incr (lua_State *L)
{
  luaL_openlib(L, "incr", testinc, 0);
  return 1;
}

