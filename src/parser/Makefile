include config.mk

CXXFLAGS := -I.. \
	    -I$(MYBUILD)/include \
	    -I$(MYSRC)/include \
	    -I$(MYSRC)/sql \
	    -I$(MYSRC)/regex \
	    -I$(MYBUILD)/sql \
	    -Wall -Wno-unused-parameter -fno-rtti -g -O2 \
	    -DHAVE_CONFIG_H -DMYSQL_SERVER -DEMBEDDED_LIBRARY -DDBUG_OFF \
	    -DMYSQL_BUILD_DIR=\"$(MYBUILD)\" \
	    -std=c++0x

LDFLAGS  := -L$(MYBUILD)/libmysqld -lmysqld \
	    -lpthread -lrt -ldl -lz -lcrypt

PROGS	 := analyze load-schema print-back nz-foo
LIBS	 := libedbproxy.so

all:	$(PROGS) $(LIBS)

$(PROGS): %: %.o libedbproxy.so
	$(CXX) $< -o $@ $(LDFLAGS) -L. -ledbproxy -Wl,-rpath=$(shell pwd)

libedbproxy.so: embedmysql.o
	$(CXX) -shared -o $@ $< $(LDFLAGS)

%.o: %.cc
	$(CXX) $(CXXFLAGS) -MD $< -c -o $@ -fPIC

.deps: $(wildcard *.d)
	perl ../tools/mergedep.pl $@ $^

-include .deps

clean:
	rm -f *.o *.d .deps $(PROGS) $(LIBS)

indent:
	uncrustify --no-backup -c ../.uncrustify.cfg $(wildcard *.cc)

.PHONY: all clean indent

# vim: set noexpandtab:
