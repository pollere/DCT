
# the code *requires* C++20 or later
CXX = clang++
CXXFLAGS = -g -O3 -I. -I../../include -Wall -Wextra
#CXXFLAGS = -g -O0 -I. -I../../include -Wall -Wextra
CXXFLAGS += -std=c++20
CXXFLAGS += -I/usr/local/include
ifeq ($(shell uname -s),Darwin)
CXXFLAGS += -I/opt/local/include
# llvm-18+ wrong libc++ bug work-around (19jan25)
LLVM = $(shell llvm-config --prefix)
LDFLAGS += -rpath $(LLVM)/lib/libc++ -rpath $(LLVM)/lib/libunwind
LDFLAGS += -L$(LLVM)/lib/libc++ -lc++ -lc++abi
endif

LIBS =
HDRS = dissect.hpp watcher.hpp
DEPS = $(HDRS)
BINS = dctwatch dctdump

all: $(BINS)

dctwatch: dctwatch.cpp $(HDRS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)
	rm -rf $@.dSYM

dctdump: dctdump.cpp $(HDRS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)
	rm -rf $@.dSYM

dctpcap: dctpcap.cpp $(HDRS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $< $(LIBS) -Ilibtins/include libtins/build/lib/libtins.a -lpcap
	rm -rf $@.dSYM

clean:
	rm -f $(BINS)
