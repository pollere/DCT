CXXFLAGS = -Wall -Wextra -g -O0 -std=c++20 -I../include
CXXFLAGS += -fsanitize=address,undefined
#CXXFLAGS = -Wall -Wextra -g -O3 -std=c++20 -I../include

ifeq ($(shell uname -s),Linux)
#CXX = clang++
CXX = c++
#CXXFLAGS += -fno-omit-frame-pointer
BISON = bison
FLEX = flex
else
CXX = clang++
BISON = /opt/local/bin/bison
FLEX = /opt/local/bin/flex
CXXFLAGS += -I/opt/local/include
# we can't fix boost warnings so suppress them
CXXFLAGS += --system-header-prefix=boost/
LDFLAGS += -L/opt/local/lib
endif

CXXFLAGS += -I/usr/local/include
LDFLAGS += -L/usr/local/lib
LIBS =  -lndn-ind -llog4cxx -lsodium -lcrypto

.DEFAULT_GOAL = all

TOOLS = schema_cert schema_info schema_dump make_cert make_bundle ls_bundle bld_dump
TESTS = tst_encodeer tst_rpacket tst_validate

all: $(TOOLS)

test: $(TESTS)


#obsolete: install schema into pib
#schema_install: schema_install.cpp 
#	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) -lsodium -lndn-ind -lcrypto
#	rm -rf $@.dSYM

default_interface: default_interface.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

schema_cert: schema_cert.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) -lsodium -lndn-ind -lcrypto
	#rm -rf $@.dSYM

schema_dump: schema_dump.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	#rm -rf $@.dSYM

schema_info: schema_info.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	#rm -rf $@.dSYM

make_cert: make_cert.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) -lsodium -lndn-ind -lcrypto
	#rm -rf $@.dSYM

make_bundle: make_bundle.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) -lsodium -lndn-ind -lcrypto
	#rm -rf $@.dSYM

ls_bundle: ls_bundle.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) -lsodium -lndn-ind -lcrypto
	#rm -rf $@.dSYM

time_signing: time_signing.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

tst_encoder: tst_encoder.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) -lsodium -lndn-ind -lcrypto
	#rm -rf $@.dSYM

tst_rpacket: tst_rpacket.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) -lsodium -lndn-ind -lcrypto
	#rm -rf $@.dSYM

tst_validate: tst_validate.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

bld_dump: bld_dump.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) -lsodium -lndn-ind -lcrypto
#	rm -rf $@.dSYM

clean:
	rm -rf *.dSYM
	rm -f $(TOOLS) $(TESTS)
