CXX = g++
CXXFLAGS = -Wall -std=c++14 -O2 -flto -pthread -fdiagnostics-color=always
LDLIBS = -lcrypto -lboost_program_options -lboost_thread
HEADERS = $(shell find . -name "*.hpp")
OBJDIR = obj
OBJS = $(OBJDIR)/main.o $(OBJDIR)/polynet.o $(OBJDIR)/polyweb.o
PREFIX = /usr/local
TARGET = shost

$(TARGET): $(OBJS)
	$(CXX) $^ $(CXXFLAGS) $(LDLIBS) -o $@

$(OBJDIR)/main.o: main.cpp $(HEADERS)
	mkdir -p $(OBJDIR)
	$(CXX) -c $< $(CXXFLAGS) -o $@

$(OBJDIR)/polynet.o: Polyweb/Polynet/polynet.cpp Polyweb/Polynet/polynet.hpp
	mkdir -p $(OBJDIR)
	$(CXX) -c $< $(CXXFLAGS) -o $@

$(OBJDIR)/polyweb.o: Polyweb/polyweb.cpp Polyweb/Polynet/polynet.hpp Polyweb/polyweb.hpp Polyweb/threadpool.hpp
	mkdir -p $(OBJDIR)
	$(CXX) -c $< $(CXXFLAGS) -o $@

.PHONY: clean install

install:
	cp $(TARGET) $(PREFIX)/bin/

clean:
	rm -rf $(TARGET) $(OBJDIR)
