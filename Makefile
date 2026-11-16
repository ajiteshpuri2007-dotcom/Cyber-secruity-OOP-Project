# PRiVY Cybersecurity Project - Windows Makefile
# Compiler: MSYS2 UCRT64 g++ 16.2.0

export PATH := C:/msys64/ucrt64/bin:$(PATH)

CXX      = C:/msys64/ucrt64/bin/g++.exe
CC       = C:/msys64/ucrt64/bin/gcc.exe

MSYS2    = C:/msys64/ucrt64

CXXFLAGS = -std=c++17 -Wall -Wextra -O2 \
           -I"src" \
           -I"$(MSYS2)/include"

CFLAGS   = -O2 -I"src"

LDFLAGS  = -L"$(MSYS2)/lib"

# Windows: Winsock2 + OpenSSL (no POSIX crypt)
API_LIBS = -lssl -lcrypto -lws2_32 -lbcrypt

SRCDIR   = src
BUILDDIR = build

COMMON_OBJECTS = \
    $(BUILDDIR)/User.o \
    $(BUILDDIR)/Admin.o \
    $(BUILDDIR)/ScanResult.o \
    $(BUILDDIR)/URLAnalyzer.o \
    $(BUILDDIR)/PhishingDetector.o

SQLITE_OBJ = $(BUILDDIR)/sq3lite.o

ENGINE  = $(BUILDDIR)/privy_engine.exe
SERVER  = $(BUILDDIR)/privy_server.exe

.PHONY: all engine server clean run

all: $(ENGINE) $(SERVER)
engine: $(ENGINE)
server: $(SERVER)

$(ENGINE): $(COMMON_OBJECTS) $(BUILDDIR)/main.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^

$(SERVER): $(COMMON_OBJECTS) $(SQLITE_OBJ) $(BUILDDIR)/api_server.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(API_LIBS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp | $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(SQLITE_OBJ): $(SRCDIR)/sq3lite.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR):
	if not exist "$(BUILDDIR)" mkdir "$(BUILDDIR)"

run: $(SERVER)
	$(SERVER) 3000 privy.db

clean:
	if exist "$(BUILDDIR)" rmdir /s /q "$(BUILDDIR)"
