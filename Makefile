# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2

# Libraries to link
LIBS = -lssl -lcrypto -lfuse3

# ========== fort++ build ==========
FORT_SRC = \
    securelettuce/fort++/main.cpp \
    securelettuce/fort++/config/conf_main.cpp \
    securelettuce/fort++/crypto/crypto.cpp \
    securelettuce/fort++/crypto/utilities.cpp 

FORT_OBJ = $(FORT_SRC:.cpp=.o)
FORT_TARGET = fort++

FORT_INCLUDES = -I./securelettuce/fort++/config -I./securelettuce/fort++/crypto

# ========== openfort build ==========
OPEN_SRC = \
    securelettuce/openvault/main.cpp \
    securelettuce/openvault/crypto/crypto.cpp \
    securelettuce/openvault/filesystem/fuse_op.cpp

OPEN_OBJ = $(OPEN_SRC:.cpp=.o)
OPEN_TARGET = openfort

OPEN_INCLUDES = -I./securelettuce/openvault/crypto -I./securelettuce/openvault/filesystem

# ========== Default rule ==========
all: $(FORT_TARGET) $(OPEN_TARGET)

# Build fort++
$(FORT_TARGET): $(FORT_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

# Build openfort
$(OPEN_TARGET): $(OPEN_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

# Compilation rule for fort++ sources
securelettuce/fort++/%.o: securelettuce/fort++/%.cpp
	$(CXX) $(CXXFLAGS) $(FORT_INCLUDES) -c $< -o $@

# Compilation rule for openfort sources
securelettuce/openvault/%.o: securelettuce/openvault/%.cpp
	$(CXX) $(CXXFLAGS) $(OPEN_INCLUDES) -c $< -o $@

# Clean build files
clean:
	rm -f $(FORT_OBJ) $(FORT_TARGET) $(OPEN_OBJ) $(OPEN_TARGET)

.PHONY: all clean

