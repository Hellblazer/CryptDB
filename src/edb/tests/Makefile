INCPATH	 :=  -I. \
		-I../  \
	    -I$(SSLPATH)/include/ \
	    -I$(GMPPATH)/include/ \
	    -I$(MYPATH)/include/\
	    -I$(LUAPATH)/include/lua5.1/\


CC	 := g++

CFG := $(MYPATH)/bin/mysql_config

HEADERS := $(wildcard ../*.h)

TEST_OBJS := test.o TestSinglePrinc.o

CFLAGS	:= -g -O2 -fno-strict-aliasing -fwrapv -fPIC \
	   -Wall -Wpointer-arith -Wendif-labels \
	   -D_GNU_SOURCE  `$(CFG) --cflags` $(INCPATH)

CXXFLAGS := $(CFLAGS)

all: test

test: $(TEST_OBJS)
	$(CC) $(LDFLAGS) $(LIBPATH) -o $@ $^  -lcryptdb -ldl -lcrypto -lntl $(ILIB)
		
%.o: %.cc %.cpp $(HEADERS)
	$(CC) $(CXXFLAGS) $< -c -o $@
	
clean: 
	rm -f *.o test
	
