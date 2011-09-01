CXX	 := g++
CXXFLAGS := -std=c++0x -I.. -Wall -Werror
LDFLAGS	 := -lcrypto -lntl

LIBOBJS	 := paillier.o urandom.o arc4.o aes.o

all:	x
.PHONY:	all

clean:
	rm -f *.o
.PHONY: all

%.o: %.cc
	$(CXX) $< -c -o $@ $(CXXFLAGS)

x: %: %.o $(LIBOBJS)
	$(CXX) $^ -o $@ $(LDFLAGS)

# vim: set noexpandtab:
