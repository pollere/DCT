#CXXFLAGS = -Wall -Wextra -Wno-shift-negative-value -g -O2 -std=c++20 -Iinclude
#CXXFLAGS = -Wall -Wextra -g -O2 -std=c++20 -Iinclude
#CXXFLAGS = -Wall -Wextra -Wno-shift-negative-value -g -O0 -std=c++20 -Iinclude
CXXFLAGS = -Wall -Wextra -g -O0 -std=c++20 -I../include
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

.DEFAULT_GOAL = schema_install

TOOLS = schema_install

all: $(TOOLS)

schema_install: schema_install.cpp 
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) -lsodium -lndn-ind -lcrypto

clean:
	rm -rf *.dSYM
	rm $(TOOLS)
