# on a mac need to set PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
# the code *requires* C++ 20 or later
#
# Clang rather than gcc is used on linux because current version
# of gcc makes it difficult to follow c++ core guidelines. E.g.,
# core guidelines suggest 'constexpr whenever possible' but
# almost all uses of 'constexpr' give fatal errors in g++-12.

INCLUDES = ../../include
CXXFLAGS = -g -O0 -I. -I$(INCLUDES) -Wall -Wextra -std=c++20 -I/opt/local/include
CXXFLAGS += -fsanitize=address
#CXXFLAGS += -fsanitize=address,undefined
#CXXFLAGS = -g -O3 -I. -I$(INCLUDES) -Wall -Wextra -std=c++20 -I/opt/local/include
DEPS = $(HDRS)
BINS = relay sens cntrl
JUNK = 

# OS dependent definitions
ifeq ($(shell uname -s),Darwin)
CXX=clang++
LIBS += -L/opt/local/lib -lsodium
JUNK += $(addsuffix .dSYM,$(BINS))
# llvm-18+ wrong libc++ bug work-around (19jan25)
LLVM = $(shell llvm-config --prefix)
LDFLAGS += -rpath $(LLVM)/lib/libc++ -rpath $(LLVM)/lib/libunwind
LDFLAGS += -L$(LLVM)/lib/libc++ -lc++ -lc++abi
else
CXX=clang++
LIBS += -lsodium
endif

#all: $(BINS)
all: relay sens cntrl

.PHONY: clean distclean tags

relay: relay.cpp $(DEPS)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

sens: sens.cpp $(DEPS)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

cntrl: cntrl.cpp $(DEPS)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

clean:
	rm -rf $(BINS) $(JUNK)

distclean: clean
