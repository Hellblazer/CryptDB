CXX	 := g++
CXXFLAGS := -std=c++0x -I.. -Wall -Werror -O2
LDFLAGS	 := -lcrypto -lntl

LIBOBJS	 := paillier.o urandom.o arc4.o
PROGS	 := x

all:	$(PROGS)
.PHONY:	all

clean:
	rm -f *.o $(PROGS)
.PHONY: all

%.o: %.cc $(wildcard *.hh)
	$(CXX) $< -c -o $@ $(CXXFLAGS)

x: %: %.o $(LIBOBJS)
	$(CXX) $^ -o $@ $(LDFLAGS)

# vim: set noexpandtab:
