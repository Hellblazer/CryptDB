#include <iostream>
//#include <lua.hpp>
#include <luabind/luabind.hpp>

void greet() {
  std::cout << "Hello lua!  It's C++ here..." << std::endl;
}

extern "C" int main (lua_State *L)
{
  using namespace luabind;
  open(L);
  module(L, "NAME")
  [
   def("greet",&greet)
  ];
  return 0;
}

