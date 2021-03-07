# on a mac need to set PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
# the code *requires* C++ 20 or later
# changed optimization to 00 for debugging - from 02
INCLUDES = ../../include
CXX=clang++
#CXXFLAGS = -g -O0 -I. -I$(INCLUDES) -Wall -std=c++20 -I/opt/local/include
CXXFLAGS = -g -O0 -I. -I$(INCLUDES) -std=c++20 -I/opt/local/include
CXXFLAGS += $(shell pkg-config --cflags libndn-ind)
LIBS = $(shell pkg-config --libs libndn-ind)
HDRS = mbps0.hpp
DEPS = $(HDRS)
BINS = app1 app2 app3
JUNK = 

# OS dependent definitions
ifeq ($(shell uname -s),Darwin)
LIBS += -lboost_iostreams-mt -llog4cxx -lsodium -lcrypto
JUNK += $(addsuffix .dSYM,$(BINS))
else
LIBS += -lboost_iostreams -llog4cxx -lpthread -lsodium -lcrypto
endif

all: $(BINS)

.PHONY: clean distclean tags

app1: app1.cpp $(DEPS)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

app2: app2.cpp $(DEPS)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

app3: app3.cpp $(DEPS)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

clean:
	rm -rf $(BINS) $(JUNK)

distclean: clean
