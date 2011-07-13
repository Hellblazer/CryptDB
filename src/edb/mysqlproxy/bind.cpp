#include <iostream>
#include <lua.hpp>

static int greet(lua_State* L) {
  std::cout << "Hello lua!  It's C++ here..." << std::endl;
  return 0;
}

static const struct luaL_reg testlib[] = 
  {
    {"greet", greet},
    {NULL, NULL}
  };

extern "C" int luaopen_test (lua_State *L)
{
  luaL_openlib(L, "test", testlib, 0);
  return 1;
}

