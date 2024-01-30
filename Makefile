# This file was auto-generated by Polybuild

compiler := $(CXX)
compilation_flags := -Wall -std=c++14 -O3 -pthread
libraries := -lssl -lcrypto -lboost_program_options -lboost_thread

default: shost
.PHONY: default

obj/main.o: ./main.cpp ./Polyweb/mimetypes.hpp ./Polyweb/string.hpp ./Polyweb/polyweb.hpp ./Polyweb/Polynet/polynet.hpp ./Polyweb/Polynet/secure_sockets.hpp ./Polyweb/Polynet/smart_sockets.hpp ./Polyweb/threadpool.hpp
	@echo -e '\033[1m[POLYBUILD]\033[0m Building $@ from $<...'
	@mkdir -p obj
	@$(compiler) -c $< $(compilation_flags) -o $@
	@echo -e '\033[1m[POLYBUILD]\033[0m Finished building $@ from $<!'

obj/server.o: Polyweb/server.cpp Polyweb/polyweb.hpp Polyweb/Polynet/polynet.hpp Polyweb/Polynet/secure_sockets.hpp Polyweb/Polynet/smart_sockets.hpp Polyweb/string.hpp Polyweb/threadpool.hpp
	@echo -e '\033[1m[POLYBUILD]\033[0m Building $@ from $<...'
	@mkdir -p obj
	@$(compiler) -c $< $(compilation_flags) -o $@
	@echo -e '\033[1m[POLYBUILD]\033[0m Finished building $@ from $<!'

obj/client.o: Polyweb/client.cpp Polyweb/polyweb.hpp Polyweb/Polynet/polynet.hpp Polyweb/Polynet/secure_sockets.hpp Polyweb/Polynet/smart_sockets.hpp Polyweb/string.hpp Polyweb/threadpool.hpp
	@echo -e '\033[1m[POLYBUILD]\033[0m Building $@ from $<...'
	@mkdir -p obj
	@$(compiler) -c $< $(compilation_flags) -o $@
	@echo -e '\033[1m[POLYBUILD]\033[0m Finished building $@ from $<!'

obj/string.o: Polyweb/string.cpp Polyweb/string.hpp
	@echo -e '\033[1m[POLYBUILD]\033[0m Building $@ from $<...'
	@mkdir -p obj
	@$(compiler) -c $< $(compilation_flags) -o $@
	@echo -e '\033[1m[POLYBUILD]\033[0m Finished building $@ from $<!'

obj/polyweb.o: Polyweb/polyweb.cpp Polyweb/polyweb.hpp Polyweb/Polynet/polynet.hpp Polyweb/Polynet/secure_sockets.hpp Polyweb/Polynet/smart_sockets.hpp Polyweb/string.hpp Polyweb/threadpool.hpp
	@echo -e '\033[1m[POLYBUILD]\033[0m Building $@ from $<...'
	@mkdir -p obj
	@$(compiler) -c $< $(compilation_flags) -o $@
	@echo -e '\033[1m[POLYBUILD]\033[0m Finished building $@ from $<!'

obj/websocket.o: Polyweb/websocket.cpp Polyweb/polyweb.hpp Polyweb/Polynet/polynet.hpp Polyweb/Polynet/secure_sockets.hpp Polyweb/Polynet/smart_sockets.hpp Polyweb/string.hpp Polyweb/threadpool.hpp
	@echo -e '\033[1m[POLYBUILD]\033[0m Building $@ from $<...'
	@mkdir -p obj
	@$(compiler) -c $< $(compilation_flags) -o $@
	@echo -e '\033[1m[POLYBUILD]\033[0m Finished building $@ from $<!'

obj/secure_sockets.o: Polyweb/Polynet/secure_sockets.cpp Polyweb/Polynet/secure_sockets.hpp Polyweb/Polynet/polynet.hpp
	@echo -e '\033[1m[POLYBUILD]\033[0m Building $@ from $<...'
	@mkdir -p obj
	@$(compiler) -c $< $(compilation_flags) -o $@
	@echo -e '\033[1m[POLYBUILD]\033[0m Finished building $@ from $<!'

obj/polynet.o: Polyweb/Polynet/polynet.cpp Polyweb/Polynet/polynet.hpp Polyweb/Polynet/secure_sockets.hpp
	@echo -e '\033[1m[POLYBUILD]\033[0m Building $@ from $<...'
	@mkdir -p obj
	@$(compiler) -c $< $(compilation_flags) -o $@
	@echo -e '\033[1m[POLYBUILD]\033[0m Finished building $@ from $<!'

shost: obj/main.o obj/server.o obj/client.o obj/string.o obj/polyweb.o obj/websocket.o obj/secure_sockets.o obj/polynet.o
	@echo -e '\033[1m[POLYBUILD]\033[0m Building $@...'
	@$(compiler) $^ $(compilation_flags) $(libraries) -o $@
	@echo -e '\033[1m[POLYBUILD]\033[0m Finished building $@!'

clean:
	@echo -e '\033[1m[POLYBUILD]\033[0m Deleting shost and obj...'
	@rm -rf shost obj
	@echo -e '\033[1m[POLYBUILD]\033[0m Finished deleting shost and obj!'
.PHONY: clean

install:
	@echo -e '\033[1m[POLYBUILD]\033[0m Copying shost to /usr/local/bin...'
	@cp shost /usr/local/bin
	@echo -e '\033[1m[POLYBUILD]\033[0m Finished copying shost to /usr/local/bin!'
.PHONY: install
