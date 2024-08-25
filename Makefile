# This file was auto-generated by Polybuild

obj_ext := .o
ifeq ($(OS),Windows_NT)
	obj_ext := .obj
	out_ext := .exe
endif

compiler := $(CXX)
compilation_flags := -Wall -std=c++17 -O3 -pthread
libraries := -lssl -lcrypto -lboost_program_options -lboost_thread

default: shost$(out_ext)
.PHONY: default

obj/main_0$(obj_ext): ./main.cpp ./Polyweb/mimetypes.hpp ./Polyweb/string.hpp ./Polyweb/Polynet/string.hpp ./Polyweb/polyweb.hpp ./Polyweb/Polynet/polynet.hpp ./Polyweb/Polynet/secure_sockets.hpp ./Polyweb/Polynet/smart_sockets.hpp ./Polyweb/threadpool.hpp
	@printf '\033[1m[POLYBUILD]\033[0m Compiling $@ from $<...\n'
	@mkdir -p obj
	@$(compiler) -c $< $(compilation_flags) -o $@
	@printf '\033[1m[POLYBUILD]\033[0m Finished compiling $@ from $<!\n'

obj/string_0$(obj_ext): Polyweb/string.cpp Polyweb/string.hpp Polyweb/Polynet/string.hpp
	@printf '\033[1m[POLYBUILD]\033[0m Compiling $@ from $<...\n'
	@mkdir -p obj
	@$(compiler) -c $< $(compilation_flags) -o $@
	@printf '\033[1m[POLYBUILD]\033[0m Finished compiling $@ from $<!\n'

obj/client_0$(obj_ext): Polyweb/client.cpp Polyweb/polyweb.hpp Polyweb/Polynet/polynet.hpp Polyweb/Polynet/string.hpp Polyweb/Polynet/secure_sockets.hpp Polyweb/Polynet/smart_sockets.hpp Polyweb/string.hpp Polyweb/threadpool.hpp
	@printf '\033[1m[POLYBUILD]\033[0m Compiling $@ from $<...\n'
	@mkdir -p obj
	@$(compiler) -c $< $(compilation_flags) -o $@
	@printf '\033[1m[POLYBUILD]\033[0m Finished compiling $@ from $<!\n'

obj/polyweb_0$(obj_ext): Polyweb/polyweb.cpp Polyweb/polyweb.hpp Polyweb/Polynet/polynet.hpp Polyweb/Polynet/string.hpp Polyweb/Polynet/secure_sockets.hpp Polyweb/Polynet/smart_sockets.hpp Polyweb/string.hpp Polyweb/threadpool.hpp
	@printf '\033[1m[POLYBUILD]\033[0m Compiling $@ from $<...\n'
	@mkdir -p obj
	@$(compiler) -c $< $(compilation_flags) -o $@
	@printf '\033[1m[POLYBUILD]\033[0m Finished compiling $@ from $<!\n'

obj/websocket_0$(obj_ext): Polyweb/websocket.cpp Polyweb/polyweb.hpp Polyweb/Polynet/polynet.hpp Polyweb/Polynet/string.hpp Polyweb/Polynet/secure_sockets.hpp Polyweb/Polynet/smart_sockets.hpp Polyweb/string.hpp Polyweb/threadpool.hpp
	@printf '\033[1m[POLYBUILD]\033[0m Compiling $@ from $<...\n'
	@mkdir -p obj
	@$(compiler) -c $< $(compilation_flags) -o $@
	@printf '\033[1m[POLYBUILD]\033[0m Finished compiling $@ from $<!\n'

obj/server_0$(obj_ext): Polyweb/server.cpp Polyweb/polyweb.hpp Polyweb/Polynet/polynet.hpp Polyweb/Polynet/string.hpp Polyweb/Polynet/secure_sockets.hpp Polyweb/Polynet/smart_sockets.hpp Polyweb/string.hpp Polyweb/threadpool.hpp
	@printf '\033[1m[POLYBUILD]\033[0m Compiling $@ from $<...\n'
	@mkdir -p obj
	@$(compiler) -c $< $(compilation_flags) -o $@
	@printf '\033[1m[POLYBUILD]\033[0m Finished compiling $@ from $<!\n'

obj/polynet_0$(obj_ext): Polyweb/Polynet/polynet.cpp Polyweb/Polynet/polynet.hpp Polyweb/Polynet/string.hpp Polyweb/Polynet/secure_sockets.hpp
	@printf '\033[1m[POLYBUILD]\033[0m Compiling $@ from $<...\n'
	@mkdir -p obj
	@$(compiler) -c $< $(compilation_flags) -o $@
	@printf '\033[1m[POLYBUILD]\033[0m Finished compiling $@ from $<!\n'

obj/secure_sockets_0$(obj_ext): Polyweb/Polynet/secure_sockets.cpp Polyweb/Polynet/secure_sockets.hpp Polyweb/Polynet/polynet.hpp Polyweb/Polynet/string.hpp
	@printf '\033[1m[POLYBUILD]\033[0m Compiling $@ from $<...\n'
	@mkdir -p obj
	@$(compiler) -c $< $(compilation_flags) -o $@
	@printf '\033[1m[POLYBUILD]\033[0m Finished compiling $@ from $<!\n'

shost$(out_ext): obj/main_0$(obj_ext) obj/string_0$(obj_ext) obj/client_0$(obj_ext) obj/polyweb_0$(obj_ext) obj/websocket_0$(obj_ext) obj/server_0$(obj_ext) obj/polynet_0$(obj_ext) obj/secure_sockets_0$(obj_ext)
	@printf '\033[1m[POLYBUILD]\033[0m Building $@...\n'
	@$(compiler) $^ $(static_libraries) $(compilation_flags) $(libraries) -o $@
	@printf '\033[1m[POLYBUILD]\033[0m Finished building $@!\n'

clean:
	@printf '\033[1m[POLYBUILD]\033[0m Deleting shost$(out_ext) and obj...\n'
	@rm -rf shost$(out_ext) obj
	@printf '\033[1m[POLYBUILD]\033[0m Finished deleting shost$(out_ext) and obj!\n'
.PHONY: clean

install:
	@printf '\033[1m[POLYBUILD]\033[0m Copying shost$(out_ext) to /usr/local/bin...\n'
	@cp shost$(out_ext) /usr/local/bin
	@printf '\033[1m[POLYBUILD]\033[0m Finished copying shost to /usr/local/bin!\n'
.PHONY: install
