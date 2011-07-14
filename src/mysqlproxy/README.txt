How to Run Mysql Proxy
----------------------

to start proxy:
  % mysql-proxy --defaults-file=./mysql-proxy.cnf

to send a single command to mysql:
  % mysql -u root -pletmein -h 127.0.0.1 -P 3307 -e 'command'

to configure mysql proxy, edit mysql-proxy.cnf


Notes
-----

to compile c++ into lua-friendly libraries: 
>g++ increment.cpp -o libincr.so -shared -fPIC -I/usr/include/lua5.1/ -llua

to compile c++ with luabind into lua-freindly libraries:
>g++ bind2.cpp -o libbind2.so -shared -L/usr/local/include/luabind/ -lluabindd -I/usr/include/lua5.1/ -llua

