# the code *requires* C++ 20 or later (i.e., clang 12 or later)
#
# Clang rather than gcc is used on linux because current version
# of gcc makes it difficult to follow c++ core guidelines. E.g.,
# core guidelines suggest 'constexpr whenever possible' but
# almost all uses of 'constexpr' give fatal errors in g++-12.

INCLUDES = ../../include
#CXXFLAGS = -g -O3 -I. -I$(INCLUDES) -Wall -Wextra -std=c++20 -I/opt/local/include
CXXFLAGS = -g -O0 -I. -I$(INCLUDES) -Wall -Wextra -std=c++20 -I/opt/local/include
CXXFLAGS += -fsanitize=address
#CXXFLAGS += -fsanitize=address,undefined
#CXXFLAGS += -ferror-limit=4
#CXXFLAGS += -fsanitize=leak
DEPS = $(HDRS)
BINS = app1 app2 app3
JUNK = 

# OS dependent definitions
ifeq ($(shell uname -s),Darwin)
CXX=clang++
LIBS += -L/opt/local/lib -lsodium
JUNK += $(addsuffix .dSYM,$(BINS))
else
# ubuntu packages are compiled with gcc and its sanitizer doesn't cooperate with clang's
#CXX=c++
#LIBS += -lpthread -lsodium
CXX=clang++
LIBS += -lsodium
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
