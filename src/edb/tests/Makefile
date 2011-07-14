HEADERS	  := $(wildcard ../*.h)
TEST_OBJS := test.o TestSinglePrinc.o
CXXFLAGS  += -I../
LDFLAGS	  += -L../

all: test

test: $(TEST_OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^ -lcryptdb -ldl -lcrypto -lntl

%.o: %.cc %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) $< -c -o $@

clean: 
	rm -f *.o test

# vim: set noexpandtab:
