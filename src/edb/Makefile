MYSQL_CONFIG	  := /usr/bin/mysql_config
MYSQL_PLUGIN_DIR  := /usr/lib/mysql/plugin

# put any machine-specific configuration into Makefile.local
-include Makefile.local

CXX	 := g++
CXXFLAGS := -g -O2 -fno-strict-aliasing -fwrapv -fPIC \
	    -Wall -Wpointer-arith -Wendif-labels \
	    -D_GNU_SOURCE \
	    $(shell $(MYSQL_CONFIG) --cflags)
LDFLAGS	 := -L. -lmysqlclient -lz -llua5.1 \
	    -Wl,-rpath=$(shell pwd)

HEADERS	 := $(wildcard *.h)

CRYPTO_OBJS  := OPE.o util.o HGD.o CryptoManager.o Equation.o
CRYPTDB_OBJS := AccessManager.o EDBClient.o Connect.o Translator.o MultiPrinc.o
PROXY_OBJS := ConnectWrapper.o

# for recursive Makefiles
export CXX CXXFLAGS LDFLAGS

all: test edb.so libexecute.so libcryptdb.so

# UDF libraries
libedbcrypto.so: $(CRYPTO_OBJS)
	$(CXX) $(LDFLAGS) -shared -o $@ $^ -lntl -lcrypto

edb.so: edb.o libedbcrypto.so
	$(CXX)   $(LDFLAGS) -shared -o $@ $^  -ldl

test: libcryptdb.so
	cd tests && $(MAKE)
#test: libedbcrypto.so Translator.o Connect.o EDBClient.o AccessManager.o test.o
#	$(CXX) $(LDFLAGS) -o $@ $^ -ledbcrypto -ldl -lcrypto $(ILIB)

libcryptdb.so: $(CRYPTDB_OBJS) libedbcrypto.so
	$(CXX) $(LDFLAGS) -shared -o $@ $(CRYPTDB_OBJS) -lntl -ldl -lcrypto -ledbcrypto

libexecute.so: $(PROXY_OBJS) libcryptdb.so libedbcrypto.so
	$(CXX) $(LDFLAGS) -shared -o $@ $(PROXY_OBJS) -lntl -ldl -lcrypto -ledbcrypto -lcryptdb

%.o: %.cc $(HEADERS)
	$(CXX) $(CXXFLAGS) $< -c -o $@

install: libedbcrypto.so installudf
	cp $< /usr/lib/

clean: 
	rm -f *.o libedbcrypto.so* edb.so*  libexecute.so libcryptdb.so 
	cd tests && $(MAKE) clean

installudf: 
	cp edb.so $(MYSQL_PLUGIN_DIR)

