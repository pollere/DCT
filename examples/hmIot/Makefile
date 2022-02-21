# on a mac need to set PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
# the code *requires* C++ 20 or later

INCLUDES = ../../include
CXXFLAGS = -g -O0 -I. -I$(INCLUDES) -Wall -Wextra -std=c++20 -I/opt/local/include
CXXFLAGS += -fsanitize=address,undefined
#CXXFLAGS += -fsanitize=leak
#CXXFLAGS = -g -O3 -I. -I$(INCLUDES) -Wall -Wextra -std=c++20 -I/opt/local/include
CXXFLAGS += $(shell pkg-config --cflags libndn-ind)
LIBS = -L/opt/local/lib $(shell pkg-config --libs libndn-ind)
HDRS = ../shims/mbps.hpp
DEPS = $(HDRS)
BINS = app1 app2 app3
JUNK = 

# OS dependent definitions
ifeq ($(shell uname -s),Darwin)
CXX=clang++
# we can't fix boost warnings so suppress them
CXXFLAGS += --system-header-prefix=boost/
LIBS += -llog4cxx -lsodium -lcrypto
JUNK += $(addsuffix .dSYM,$(BINS))
else
# ubuntu packages are compiled with gcc and its sanitizer doesn't cooperate with clang's
CXX=c++
LIBS += -llog4cxx -lpthread -lsodium -lcrypto
endif

#all: $(BINS)
all: app1 app2 app3

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
