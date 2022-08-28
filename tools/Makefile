CXXFLAGS = -Wall -Wextra -g -O0 -std=c++20 -I../include
CXXFLAGS += -fsanitize=address,undefined
CXXFLAGS += -ferror-limit=3
#CXXFLAGS = -Wall -Wextra -g -O3 -std=c++20 -I../include

ifeq ($(shell uname -s),Linux)
#CXX = clang++
CXX = c++
#CXXFLAGS += -fno-omit-frame-pointer
else
CXX = clang++
CXXFLAGS += -I/opt/local/include
# we can't fix boost warnings so suppress them
CXXFLAGS += --system-header-prefix=boost/
LDFLAGS += -L/opt/local/lib
endif

CXXFLAGS += -I/usr/local/include
LDFLAGS += -L/usr/local/lib
#LIBS =  -lndn-ind -llog4cxx -lsodium -lcrypto
LIBS =  -lsodium

.DEFAULT_GOAL = all

TOOLS = schema_cert schema_info schema_dump make_cert make_bundle ls_bundle bld_dump schemaCompile bundle_info
TESTS = tst_encodeer tst_rpacket tst_validate tst_transport time_signing

all: $(TOOLS)

test: $(TESTS)


default_interface: default_interface.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

schema_cert: schema_cert.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

schema_dump: schema_dump.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	#rm -rf $@.dSYM

schema_info: schema_info.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	#rm -rf $@.dSYM

make_cert: make_cert.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

make_bundle: make_bundle.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

ls_bundle: ls_bundle.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

bundle_info: bundle_info.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

time_signing: time_signing.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

tst_cert: tst_cert.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

tst_encoder: tst_encoder.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

tst_crpack: tst_crpack.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

tst_rpacket: tst_rpacket.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

tst_transport: tst_transport.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

tst_validate: tst_validate.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

bld_dump: bld_dump.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)
#	rm -rf $@.dSYM

schemaCompile:
	(cd compiler; make); mv compiler/schemaCompile .

clean:
	rm -rf *.dSYM
	rm -f $(TOOLS) $(TESTS)
	cd compiler; make clean
