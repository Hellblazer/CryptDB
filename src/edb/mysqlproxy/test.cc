#include <lua.hpp>

lua_State* L;

static int chello(lua_State *L) {
  lua_pushstring(L, "Hello from C++");
  return 1;
}

int main(int argc, char *argv[]) {
  L = lua_open();
  //lua_pushcfunction(L,chello);
  //lua_setglobal(L,"chello");
  luaL_openlibs(L);
  lua_register(L,"chello",chello);
  luaL_dofile(L,"test.lua");
  lua_getglobal(L,"lhello");
  lua_call(L,0,0);
  lua_close(L);
  printf("Press enter to exit...");
  getchar();
  return 0;
}
