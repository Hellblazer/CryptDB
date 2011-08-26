Installing mysql-proxy
----------------------

Use mysql-proxy version 0.9.0 or above.  Earlier versions are buggy.
To get the development version of mysql-proxy (since 0.9.0 does not
appear to be released yet):

  % bzr branch lp:mysql-proxy
  % cd mysql-proxy
  % sh ./autogen.sh
  % ./configure --enable-maintainer-mode --with-lua=lua5.1
  % make
  % make install
  % 

How to Run Mysql Proxy
----------------------

to start proxy:
  % export EDBDIR=<...>/cryptdb/src/edb
  % mysql-proxy --plugins=proxy \
                --event-threads=4 \
		--max-open-files=1024 \
		--proxy-lua-script=$EDBDIR/../mysqlproxy/wrapper.lua \
		--proxy-address=localhost:3307 \
		--proxy-backend-addresses=localhost:3306

to specify username / password / db for proxy, run before starting proxy:

  % export CRYPTDB_USER=...
  % export CRYPTDB_PASS=...
  % export CRYPTDB_DB=...

to send a single command to mysql:
  % mysql -u root -pletmein -h 127.0.0.1 -P 3307 -e 'command'


Notes
-----

to compile c++ into lua-friendly libraries: 
  % g++ attic/increment.cc -o libincr.so -shared -fPIC \
	-I/usr/include/lua5.1/ -llua

to compile c++ with luabind into lua-freindly libraries:
  % g++ attic/bind2.cc -o libbind2.so -shared -L/usr/local/include/luabind/ \
	-lluabindd -I/usr/include/lua5.1/ -llua

