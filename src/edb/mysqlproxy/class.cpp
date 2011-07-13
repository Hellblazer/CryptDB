#include <iostream>
#include <string>
#include <luabind/luabind.hpp>

class Incr {
  int cur;
 public:
  Incr(int in);
  int get_cur(void);
};

Incr::Incr(int in) {
  cur = in;
}

int Incr::get_cur(void) {
  cur++;
  return cur;
}
/*
int main() {
  Incr I = Incr(0);
  std::cout << I.get_cur() <<std::endl;
  std::cout << I.get_cur() <<std::endl;
  std::cout << I.get_cur() <<std::endl;
  return 0;
}
*/

static int incrClass(lua_State *L) {
  int n = lua_gettop(L);
  /*
  if (n != 1) {
    return luaL_error(L, "Got %d arguements instead the one I needed.  Please go check that you're not doing something monumentally stupid.", n);
  }
  */

  Incr **I = (Incr **)lua_newuserdata(L, sizeof(Incr *));
  int in = luaL_checknumber(L,1);
  *I = new Incr(in);

  lua_getglobal(L, "Incr");
  lua_setmetatable(L,-2);

  return 1;
}
  
static const struct luaL_reg IncrFunc[] = 
  {
    {"new", incrClass},
    {"get_cur",&Incr::get_cur},
    {NULL, NULL}
  };

void registerIncr(lua_State *L)
{
  luaL_register(L,"Incr",IncrFunc);
  lua_pushvalue(L,-1);
  lua_setfield(L,-2,"__index");
}
