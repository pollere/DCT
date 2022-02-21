
# the code *requires* C++20 or later
CXX = clang++
CXXFLAGS = -g -O2 -I. -I../../include -Wall -Wextra
CXXFLAGS += -std=c++20
CXXFLAGS += -I/opt/local/include
CXXFLAGS += -I/usr/local/include

LIBS =
HDRS = dissect.hpp watcher.hpp
DEPS = $(HDRS)
BINS = dctwatch dctdump

all: $(BINS)

dctwatch: dctwatch.cpp $(HDRS)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)
	rm -rf $@.dSYM

dctdump: dctdump.cpp $(HDRS)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)
	rm -rf $@.dSYM

clean:
	rm -f $(BINS)
