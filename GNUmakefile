## Copy conf/config.mk.sample to conf/config.mk and adjust accordingly.
include conf/config.mk

OBJDIR	 := obj
TOP	 := $(shell echo $${PWD-`pwd`})
CXX	 := g++
CXXFLAGS := -g -O2 -fno-strict-aliasing -fno-rtti -fwrapv -fPIC \
	    -Wall -Werror -Wpointer-arith -Wendif-labels -Wformat=2  \
	    -Wextra -Wmissing-noreturn -Wwrite-strings -Wno-unused-parameter \
	    -Wmissing-format-attribute -Wswitch-default \
	    -Wmissing-declarations -Wshadow -Woverloaded-virtual \
	    -Wcast-qual -Wunreachable-code -Wcast-align \
	    -D_GNU_SOURCE -std=c++0x -I$(TOP)
LDFLAGS	 := -lz -llua5.1 -lntl

CXXFLAGS += -I$(MYBUILD)/include \
	    -I$(MYSRC)/include \
	    -I$(MYSRC)/sql \
	    -I$(MYSRC)/regex \
	    -I$(MYBUILD)/sql \
	    -DHAVE_CONFIG_H -DMYSQL_SERVER -DEMBEDDED_LIBRARY -DDBUG_OFF \
	    -DMYSQL_BUILD_DIR=\"$(MYBUILD)\"
LDFLAGS	 += -L$(MYBUILD)/libmysqld -lmysqld -lpthread -lrt -ldl -lz -lcrypt

## To be populated by Makefrag files
OBJDIRS	:=

.PHONY: all
all:

.PHONY: clean
clean:
	rm -rf $(OBJDIR)

# Eliminate default suffix rules
.SUFFIXES:

# Delete target files if there is an error (or make is interrupted)
.DELETE_ON_ERROR:

# make it so that no intermediate .o files are ever deleted
.PRECIOUS: %.o

$(OBJDIR)/.deps: $(foreach dir, $(OBJDIRS), $(wildcard $(OBJDIR)/$(dir)/*.d))
	@mkdir -p $(@D)
	perl mergedep.pl $@ $^
-include $(OBJDIR)/.deps

$(OBJDIR)/%.o: %.cc
	@mkdir -p $(@D)
	$(CXX) -MD $(CXXFLAGS) -c $< -o $@

$(OBJDIR)/%.so:
	$(CXX) -shared -o $@ $^ $(LDFLAGS)

include crypto/Makefrag

# vim: set noexpandtab:
