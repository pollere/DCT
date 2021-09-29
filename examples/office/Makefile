# on a mac need to set PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
# the code *requires* C++ 20 or later

INCLUDES = ../../include
CXXFLAGS = -g -O0 -I. -I$(INCLUDES) -Wall -Wextra -std=c++20 -I/opt/local/include
CXXFLAGS += -fsanitize=address,undefined
#CXXFLAGS = -g -O3 -I. -I$(INCLUDES) -Wall -Wextra -std=c++20 -I/opt/local/include
CXXFLAGS += $(shell pkg-config --cflags libndn-ind)
LIBS = -L/opt/local/lib $(shell pkg-config --libs libndn-ind)
HDRS = ../shims/mbps.hpp
DEPS = $(HDRS)
BINS = phone room
JUNK = 

# OS dependent definitions
ifeq ($(shell uname -s),Darwin)
CXX=clang++
# we can't fix boost warnings so suppress them
CXXFLAGS += --system-header-prefix=boost/
LIBS += -lboost_iostreams-mt -llog4cxx -lsodium -lcrypto
JUNK += $(addsuffix .dSYM,$(BINS))
else
# ubuntu packages are compiled with gcc and its sanitizer doesn't cooperate with clang's
CXX=c++
LIBS += -lboost_iostreams -llog4cxx -lpthread -lsodium -lcrypto
endif

#all: $(BINS)
all: phone room

.PHONY: clean distclean tags

phone: phone.cpp $(DEPS)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

room: room.cpp $(DEPS)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

clean:
	rm -rf $(BINS) $(JUNK)

distclean: clean
