MYSQL_CONFIG	  := /usr/bin/mysql_config
MYSQL_PLUGIN_DIR  := /usr/lib/mysql/plugin

# put any machine-specific configuration into Makefile.local
-include Makefile.local

CXX	 := g++
CXXFLAGS := -g -O2 -fno-strict-aliasing -fwrapv -fPIC \
	    -Wall -Wpointer-arith -Wendif-labels \
	    -D_GNU_SOURCE -std=c++0x \
	    $(shell $(MYSQL_CONFIG) --cflags)
LDFLAGS	 := -L. -lmysqlclient -lz -llua5.1 \
	    -Wl,-rpath=$(shell pwd)

HEADERS	 := $(wildcard *.h)

CRYPTO_OBJS  := OPE.o util.o HGD.o CryptoManager.o Equation.o
CRYPTDB_OBJS := AccessManager.o EDBClient.o Connect.o Translator.o MultiPrinc.o
PROXY_OBJS   := ConnectWrapper.o
LIBS	     := libedbcrypto.so edb.so libcryptdb.so libexecute.so

# for recursive Makefiles
export CXX CXXFLAGS LDFLAGS

all: $(LIBS) test

# UDF libraries
libedbcrypto.so: $(CRYPTO_OBJS)
	$(CXX) $(LDFLAGS) -shared -o $@ $^ -lntl -lcrypto

edb.so: edb.o libedbcrypto.so
	$(CXX)   $(LDFLAGS) -shared -o $@ $^  -ldl

libcryptdb.so: $(CRYPTDB_OBJS) libedbcrypto.so
	$(CXX) $(LDFLAGS) -shared -o $@ $(CRYPTDB_OBJS) -lntl -ldl -lcrypto -ledbcrypto

libexecute.so: $(PROXY_OBJS) libcryptdb.so libedbcrypto.so
	$(CXX) $(LDFLAGS) -shared -o $@ $(PROXY_OBJS) -lntl -ldl -lcrypto -ledbcrypto -lcryptdb

test: libcryptdb.so
	cd tests && $(MAKE)

%.o: %.cc $(HEADERS)
	$(CXX) $(CXXFLAGS) $< -c -o $@

install: libedbcrypto.so edb.so
	install -m 644 libedbcrypto.so /usr/lib
	install -m 644 edb.so $(MYSQL_PLUGIN_DIR)

clean:
	rm -f *.o $(LIBS)
	cd tests && $(MAKE) clean

indent:
	uncrustify --no-backup -c ../.uncrustify.cfg $(wildcard *.cc)
	uncrustify --no-backup -c ../.uncrustify.cfg $(wildcard *.h)
	uncrustify --no-backup -c ../.uncrustify.cfg $(wildcard tests/*.cc)
	uncrustify --no-backup -c ../.uncrustify.cfg $(wildcard tests/*.h)

.PHONY: install clean indent test

# vim: set noexpandtab:
