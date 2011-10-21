OBJDIR	 := obj
TOP	 := $(shell echo $${PWD-`pwd`})
CXX	 := g++
CXXFLAGS := -O2 -fno-strict-aliasing -fno-rtti -fwrapv -fPIC \
	    -Wall -Werror -Wpointer-arith -Wendif-labels -Wformat=2  \
	    -Wextra -Wmissing-noreturn -Wwrite-strings -Wno-unused-parameter \
	    -Wmissing-declarations -Woverloaded-virtual \
	    -Wunreachable-code -D_GNU_SOURCE -std=c++0x -I$(TOP)
LDFLAGS	 := -lz -llua5.1 -lcrypto -lntl \
	    -L$(TOP)/$(OBJDIR) -Wl,-rpath=$(TOP)/$(OBJDIR) -Wl,-rpath=$(TOP)

## Copy conf/config.mk.sample to conf/config.mk and adjust accordingly.
include conf/config.mk

CXXFLAGS += -I$(MYBUILD)/include \
	    -I$(MYSRC)/include \
	    -I$(MYSRC)/sql \
	    -I$(MYSRC)/regex \
	    -I$(MYBUILD)/sql \
	    -DHAVE_CONFIG_H -DMYSQL_SERVER -DEMBEDDED_LIBRARY -DDBUG_OFF \
	    -DMYSQL_BUILD_DIR=\"$(MYBUILD)\"
LDFLAGS	 += -lpthread -lrt -ldl -lcrypt -lreadline

## To be populated by Makefrag files
OBJDIRS	:=

.PHONY: all
all:

.PHONY: install
install:

.PHONY: clean
clean:
	rm -rf $(OBJDIR)

# Eliminate default suffix rules
.SUFFIXES:

# Delete target files if there is an error (or make is interrupted)
.DELETE_ON_ERROR:

# make it so that no intermediate .o files are ever deleted
.PRECIOUS: %.o

$(OBJDIR)/%.o: %.cc
	@mkdir -p $(@D)
	$(CXX) -MD $(CXXFLAGS) -c $< -o $@

include crypto/Makefrag
include crypto-old/Makefrag
include edb/Makefrag
include parser/Makefrag
include test/Makefrag
include util/Makefrag
include udf/Makefrag
include mysqlproxy/Makefrag

$(OBJDIR)/.deps: $(foreach dir, $(OBJDIRS), $(wildcard $(OBJDIR)/$(dir)/*.d))
	@mkdir -p $(@D)
	perl mergedep.pl $@ $^
-include $(OBJDIR)/.deps

# .PHONY: indent
# indent:
#	uncrustify --no-backup -c conf/uncrustify.cfg $(wildcard *.cc)

# vim: set noexpandtab:
