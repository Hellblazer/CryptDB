include config.mk

CXXFLAGS := -I. \
	    -I$(MYBUILD)/include \
	    -I$(MYSRC)/include \
	    -I$(MYSRC)/sql \
	    -I$(MYSRC)/regex \
	    -I$(MYBUILD)/sql \
	    -Wall -Wno-unused-parameter -fno-rtti -g -O2 \
	    -DHAVE_CONFIG_H -DMYSQL_SERVER -DHAVE_EVENT_SCHEDULER -DDBUG_OFF \
	    -DMYSQL_BUILD_DIR=\"$(MYBUILD)\" \
	    -std=c++0x

LDFLAGS  := -L$(MYBUILD)/libmysqld -lsql_embedded \
	    -L$(MYBUILD)/sql -lpartition \
	    -L$(MYBUILD)/storage/perfschema -lperfschema \
	    -L$(MYBUILD)/storage/myisam -lmyisam \
	    -L$(MYBUILD)/storage/myisammrg -lmyisammrg \
	    -L$(MYBUILD)/storage/heap -lheap \
	    -L$(MYBUILD)/storage/csv -lcsv \
	    -L$(MYBUILD)/storage/innobase -linnobase \
	    -L$(MYBUILD)/vio -lvio \
	    -L$(MYBUILD)/regex -lregex \
	    -L$(MYBUILD)/mysys -lmysys \
	    -L$(MYBUILD)/strings -lstrings \
	    -lpthread -lrt -ldl -lz -lcrypt -lbsd

all:	parsetest xftest analyze

parsetest: parsetest.o mysql_glue.o
	$(CXX) $^ -o $@ $(LDFLAGS)

xftest: xftest.o mysql_glue.o
	$(CXX) $^ -o $@ $(LDFLAGS)

analyze: analyze.o
	$(CXX) $^ -o $@ $(LDFLAGS)

%.o: %.cc $(wildcard *.h)
	$(CXX) $(CXXFLAGS) $< -c -o $@

clean:
	rm -f *.o parsetest xftest analyze

indent:
	uncrustify --no-backup -c ../.uncrustify.cfg $(wildcard *.cc)

.PHONY: all clean indent

# vim: set noexpandtab:
