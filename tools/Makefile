CXXFLAGS = -g -O0 -std=c++20 -I../include
#CXXFLAGS += -Wall -Wextra
CXXFLAGS += -fsanitize=address,undefined
#CXXFLAGS += -fuse-ld=/opt/local/libexec/llvm-19/bin/ld64.lld
#CXXFLAGS = -Wall -Wextra -g -O3 -std=c++20 -I../include

ifeq ($(shell uname -s),Linux)
CXX = clang++
#CXX = c++
#CXXFLAGS += -fno-omit-frame-pointer
else
CXX = clang++
CXXFLAGS += -I/opt/local/include
# we can't fix boost warnings so suppress them
CXXFLAGS += --system-header-prefix=boost/
LDFLAGS += -L/opt/local/lib
# llvm-18+ wrong libc++ bug work-around (19jan25)
LLVM = $(shell llvm-config --prefix)
LDFLAGS += -rpath $(LLVM)/lib/libc++ -rpath $(LLVM)/lib/libunwind
LDFLAGS += -L$(LLVM)/lib/libc++ -lc++ -lc++abi
endif

CXXFLAGS += -I/usr/local/include
LDFLAGS += -L/usr/local/lib
LIBS =  -lsodium

.DEFAULT_GOAL = all

TOOLS = schemaCompile bld_dump bundle_info default_interface ls_bundle \
	make_bundle make_cert schema_cert schema_dump schema_info

TESTS = time_hashing time_signing tst_cert tst_certstore tst_crname \
	tst_crpack tst_encoder tst_rpacket tst_transport tst_transport \
	tst_validate

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
	$(CXX) $(CXXFLAGS) -Wall -Wextra -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

tst_certstore: tst_certstore.cpp 
	$(CXX) $(CXXFLAGS) -Wall -Wextra -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

tst_crname: tst_crname.cpp 
	$(CXX) $(CXXFLAGS) -Wall -Wextra -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

tst_crpack: tst_crpack.cpp 
	$(CXX) $(CXXFLAGS) -Wall -Wextra -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

tst_tdvclock: tst_tdvclock.cpp 
	$(CXX) $(CXXFLAGS) -Wall -Wextra -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

tst_encoder: tst_encoder.cpp 
	$(CXX) $(CXXFLAGS) -Wall -Wextra -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

tst_iblt: tst_iblt.cpp 
	$(CXX) $(CXXFLAGS) -Wall -Wextra -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

tst_rand: tst_rand.cpp 
	$(CXX) $(CXXFLAGS) -Wall -Wextra -o $@ $< $(LDFLAGS) $(LIBS)
	#rm -rf $@.dSYM

tst_rpacket: tst_rpacket.cpp 
	$(CXX) $(CXXFLAGS) -Wall -Wextra -o $@ $< $(LDFLAGS) $(LIBS)
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
