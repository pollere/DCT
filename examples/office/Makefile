# on a mac need to set PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
# the code *requires* C++ 20 or later

INCLUDES = ../../include
#CXXFLAGS = -g -O3 -I. -I$(INCLUDES) -Wall -Wextra -std=c++20 -I/opt/local/include
CXXFLAGS = -g -O0 -I. -I$(INCLUDES) -Wall -Wextra -std=c++20 -I/opt/local/include
CXXFLAGS += -fsanitize=address
#CXXFLAGS += -fsanitize=address,undefined
HDRS = 
DEPS = $(HDRS)
BINS = phone room
JUNK = 

# OS dependent definitions
CXX=clang++
ifeq ($(shell uname -s),Darwin)
LIBS += -L/opt/local/lib -lsodium
JUNK += $(addsuffix .dSYM,$(BINS))
else
LIBS += -lsodium
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
