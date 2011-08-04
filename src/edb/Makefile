MYSQL_CONFIG	  := /usr/bin/mysql_config
MYSQL_PLUGIN_DIR  := /usr/lib/mysql/plugin

# put any machine-specific configuration into Makefile.local
-include Makefile.local

CXX	 := g++
CXXFLAGS := -g -O2 -fno-strict-aliasing -fwrapv -fPIC \
	    -Wall -Werror -Wpointer-arith -Wendif-labels -Wformat=2  \
	    -Wextra -Wmissing-noreturn -Wwrite-strings -Wno-unused-parameter \
	    -Wmissing-format-attribute -Wswitch-default \
	    -Wmissing-declarations -Wshadow -Woverloaded-virtual \
	    -Wconversion -Wcast-qual -Wunreachable-code -Wcast-align \
	    -D_GNU_SOURCE -std=c++0x \
	    $(shell $(MYSQL_CONFIG) --cflags)
LDFLAGS	 := -L. -lmysqlclient -lz -llua5.1 \
	    -Wl,-rpath=$(shell pwd)

HEADERS	 := $(wildcard *.h)

CRYPTO_OBJS  := OPE.o util.o HGD.o Binary.o SWPSearch.o BasicCrypto.o ECJoin.o CryptoManager.o Equation.o cryptdb_log.o pbkdf2.o
CRYPTDB_OBJS := AccessManager.o EDBClient.o Connect.o Translator.o MultiPrinc.o
PROXY_OBJS   := ConnectWrapper.o
TEST_OBJS    := tests/test.o tests/TestSinglePrinc.o tests/TestCrypto.o tests/test_utils.o tests/TestMultiPrinc.o tests/TestAccessManager.o tests/TestProxy.o
LIBS	     := libedbcrypto.so edb.so libcryptdb.so libexecute.so

all: $(LIBS) tests/test
test: tests/test

# UDF libraries
libedbcrypto.so: $(CRYPTO_OBJS)
	$(CXX) -shared -o $@ $^ $(LDFLAGS) -lntl -lcrypto

edb.so: edb.o libedbcrypto.so
	$(CXX) -shared -o $@ $< $(LDFLAGS) -ledbcrypto -ldl

libcryptdb.so: $(CRYPTDB_OBJS) libedbcrypto.so
	$(CXX) -shared -o $@ $(CRYPTDB_OBJS) $(LDFLAGS) -lntl -ldl -lcrypto -ledbcrypto

libexecute.so: $(PROXY_OBJS) libcryptdb.so libedbcrypto.so
	$(CXX) -shared -o $@ $(PROXY_OBJS) $(LDFLAGS) -lntl -ldl -lcrypto -ledbcrypto -lcryptdb

tests/test: libcryptdb.so $(TEST_OBJS)
	$(CXX) -o $@ $(TEST_OBJS) $(LDFLAGS) -lcryptdb -ldl -lcrypto -lntl -ledbcrypto

%.o: %.cc $(HEADERS)
	$(CXX) $(CXXFLAGS) $< -c -o $@

$(TEST_OBJS): %.o: %.cc $(HEADERS) $(wildcard tests/*.h)
	$(CXX) $(CXXFLAGS) $< -c -o $@ -I.

install: libedbcrypto.so edb.so
	install -m 644 libedbcrypto.so /usr/lib
	install -m 644 edb.so $(MYSQL_PLUGIN_DIR)

clean:
	rm -f *.o tests/*.o $(LIBS) tests/test

indent:
	uncrustify --no-backup -c ../.uncrustify.cfg $(wildcard *.cc)
	uncrustify --no-backup -c ../.uncrustify.cfg $(wildcard *.h)
	uncrustify --no-backup -c ../.uncrustify.cfg $(wildcard tests/*.cc)
	uncrustify --no-backup -c ../.uncrustify.cfg $(wildcard tests/*.h)

.PHONY: all install clean indent test

# vim: set noexpandtab:
