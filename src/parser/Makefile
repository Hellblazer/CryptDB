include config.mk

CXXFLAGS := -I. \
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

all:	parsetest xftest analyze load-schema

parsetest xftest: %: %.o mysql_glue.o
	$(CXX) $^ -o $@ $(LDFLAGS)

load-schema analyze: %: %.o
	$(CXX) $^ -o $@ $(LDFLAGS)

%.o: %.cc $(wildcard *.h)
	$(CXX) $(CXXFLAGS) $< -c -o $@

clean:
	rm -f *.o parsetest xftest analyze

indent:
	uncrustify --no-backup -c ../.uncrustify.cfg $(wildcard *.cc)

.PHONY: all clean indent

# vim: set noexpandtab:
