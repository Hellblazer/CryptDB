#include <iostream>
#include <string>
#include <lua.hpp>

int value = 1;
int num_keys = 0;

class Mine {
  int i;
public:
  Mine(int in);
  void set_i(int in);
  int get_i();
};

void Mine::set_i(int in) {
  i = in;
}

Mine::Mine(int in) {
  i = in;
}

int Mine::get_i() {
  return i;
}

Mine *M;

static int lmine(lua_State *L) {
  int in = luaL_checknumber(L,1);
  M = new Mine(in);
  return 0;
}

static int lset_i(lua_State *L) {
  int in = luaL_checknumber(L,1);
  M->set_i(in);
  return 0;
}

static int lget_i(lua_State *L) {
  int out = M->get_i();
  lua_pushnumber(L,out);
  return 1;
}

void set_value(int in) {
  value = in;
  num_keys = 0;
}

static int lset_value(lua_State* L) {
  int in = luaL_checknumber(L,1);
  set_value(in);
  return 0;
}

std::string enc(std::string m) {
  num_keys++;
  int tonum = int(m[m.length()-1])+value;
  m[m.length()-1] = char(tonum);
  return m;
}

static int lenc(lua_State* L) {
  std::string m = luaL_checkstring(L,1);
  m = enc(m);
  lua_pushstring(L,m.c_str());
  return 1;
}

std::string dec(std::string c) {
  int tonum = int(c[c.length()-1])-value;
  c[c.length()-1] = char(tonum);
  return c;
}

static int ldec(lua_State* L) {
  std::string c = luaL_checkstring(L,1);
  c = dec(c);
  lua_pushstring(L,c.c_str());
  return 1;
}

int get_num() {
  return num_keys;
}

static int lget_num(lua_State* L) {
  int num = get_num();
  lua_pushnumber(L,num);
  return 1;
}

/*
int main() {
  set_value(1);
  std::cout << "aaa encrypts to " << enc("aaa") <<std::endl;
  std::cout << "aab decrypts to " << dec("aab") <<std::endl;
  std::cout << "there have been " << get_num() << " encryptions" <<std::endl;
  return 0;
}
*/

static const struct luaL_reg globvars[] =
  {
    {"set_value", lset_value},
    {"enc", lenc},
    {"dec", ldec},
    {"get_num", lget_num},
    {"set_i",lset_i},
    {"get_i",lget_i},
    {"mine",lmine},
    {NULL, NULL}
  };

extern "C" int luaopen_globals (lua_State *L)
{
  luaL_openlib(L, "globals", globvars, 0);
  return 1;
}
