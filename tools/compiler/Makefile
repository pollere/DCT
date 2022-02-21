INCLUDES = ../../include
CXXFLAGS = -Wall -Wextra -g -O0 -std=c++20 -I$(INCLUDES)
CXXFLAGS += -fsanitize=address,undefined
ifeq ($(shell uname -s),Linux)
CXX = clang++
#CXX = c++
BISON = bison
FLEX = flex
#CXXFLAGS += -fsanitize=address -fno-omit-frame-pointer -shared-libasan
#CXXFLAGS += -fsanitize=address -fno-omit-frame-pointer
#CXXFLAGS += -fsanitize=memory -fPIE -pie -fno-omit-frame-pointer -shared-libasan
else
CXX = /opt/local/bin/clang++
BISON = /opt/local/bin/bison
FLEX = /opt/local/bin/flex
CXXFLAGS += -I/opt/local/include
LDFLAGS += -L/opt/local/lib
endif
CXXFLAGS += -DCOMPILER_VERSION='"$(shell git describe --tags --long)"'

HEADERS = dag.hpp driver.hpp names.hpp output.hpp symtab.hpp semantics.hpp
SRCS = parser.ypp scanner.lpp

.DEFAULT_GOAL = schemaCompile

all: schemaCompile $(TOOLS)

%.cpp %.hpp: %.ypp
	$(BISON) -Wall $(BISONFLAGS) -o $*.cpp $<

%.cpp: %.lpp
	$(FLEX) $(FLEXFLAGS) -o$@ $<

schemaCompile: parser.cpp scanner.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -o $@ parser.cpp scanner.cpp

.SECONDARY: parser.cpp scanner.cpp

clean:
	rm -f parser.o scanner.o parser.cpp parser.hpp scanner.cpp location.hpp schemaCompile
	rm -rf schemaCompile.dSYM
