CXX	 := g++-4.6
CXXFLAGS := -std=c++0x -I.. -Wall -Werror -O2
LDFLAGS	 := -lcrypto -lntl

LIBOBJS	 := paillier.o urandom.o arc4.o hgd.o ope.o
PROGS	 := x

all:	$(PROGS)
.PHONY:	all

clean:
	rm -f *.o *.d .deps $(PROGS)
.PHONY: all

%.o: %.cc
	$(CXX) -MD $(CXXFLAGS) -c $< -o $@

.deps: $(wildcard *.d)
	perl ../tools/mergedep.pl $@ $^

-include .deps

$(PROGS): %: %.o $(LIBOBJS)
	$(CXX) $^ -o $@ $(LDFLAGS)

# vim: set noexpandtab:
