#include <iostream>
#include <string>
#include <luabind/luabind.hpp>

class Incr {
  int value;
  int num_keys;
public:
  Incr(int in);
  std::string enc(std::string m);
  std::string dec(std::string c);
  int get_num();
};

Incr::Incr(int in) {
  value = in;
  num_keys = 0;
}

std::string Incr::enc(std::string m) {
  num_keys++;
  int tonum = int(m[m.length()-1])+value;
  m[m.length()-1] = char(tonum);
  return m;
}

std::string Incr::dec(std::string c) {
  int tonum = int(c[c.length()-1])-value;
  c[c.length()-1] = char(tonum);
  return c;
}

int Incr::get_num() {
  return num_keys;
}

extern "C" int init(lua_State *L)
{
  using namespace luabind;
  open(L);
  module(L) [
	     class_<Incr>("Incr")
	     .def(constructor<int>())
	     //.def_readonly("cur",&Incr::cur)
	     .def("enc",&Incr::enc)
	     .def("dec",&Incr::dec)
	     .def("get_num",&Incr::get_num)
	     ];
  return 0;
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
/*
class testclass
{
public:
  testclass(const std::string& s): m_string(s) {};
  void print_string() { std::cout << m_string << "\n"; }

private:
  std::string m_string;
};

extern "C" int init(lua_State *L)
{
  using namespace luabind;
  open(L);
  module(L) [
	     class_<testclass>("testclass")
	     .def(constructor<const std::string&>())
	     .def("print_string",&testclass::print_string)
	     ];
  return 0;
}
*/
