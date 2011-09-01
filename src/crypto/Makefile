CXX	 := g++
CXXFLAGS := -std=c++0x -I.. -Wall -Werror

OBJS	 := paillier.o urandom.o arc4.o aes.o

all:	$(OBJS)
.PHONY:	all

clean:
	rm -f $(OBJS)
.PHONY: all

%.o: %.cc
	$(CXX) $< -c -o $@ $(CXXFLAGS)

# vim: set noexpandtab:
