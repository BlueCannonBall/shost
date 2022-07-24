#include "Polyweb/mimetypes.hpp"
#include "Polyweb/polyweb.hpp"
#include <fstream>
#include <iostream>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

inline std::string get_time() {
    time_t t = time(0);
    struct tm* now = localtime(&t);
    char time_cstr[50] = {0};
    strftime(time_cstr, sizeof(time_cstr), "%a %b %d %H:%M:%S %Y", now);
    return time_cstr;
}

const char* sockaddr_to_string(const struct sockaddr* addr) {
    static char ret[1024];
    memset(ret, 0, sizeof(ret));

    switch (addr->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in*) addr)->sin_addr), ret, sizeof(ret));
            break;

        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6*) addr)->sin6_addr), ret, sizeof(ret));
            break;

        default:
            return "Unknown AF";
    }

    return ret;
}

int main(int argc, char** argv) {
    pn::init(true);
    signal(SIGPIPE, SIG_IGN);

    std::string port = "8000";
    if (argc >= 2) {
        port = argv[1];
    }

    pw::Server server;

    server.route("/",
        pw::HTTPRoute {
            [](const pw::Connection& conn, const pw::HTTPRequest& req) -> pw::HTTPResponse {
                std::cout << '[' << get_time() << "] " << sockaddr_to_string(&conn.addr) << " - \"" << req.method << ' ' << req.target << ' ' << req.http_version << "\"" << std::endl;

                std::string filename = "." + req.target;

                struct stat s;
                if (stat(filename.c_str(), &s) == -1) {
                    if (errno == ENOENT || errno == ENOTDIR) {
                        return pw::HTTPResponse::create_basic("404");
                    } else {
                        std::cerr << "Error: Stat failed: " << strerror(errno) << std::endl;
                        return pw::HTTPResponse::create_basic("500");
                    }
                }

                if (S_ISDIR(s.st_mode)) {
                    filename += "/index.html";
                }

                std::ifstream file(filename, std::ios::binary | std::ios::ate);
                if (!file.is_open()) {
                    return pw::HTTPResponse::create_basic("404");
                }

                std::streamsize size = file.tellg();
                file.seekg(0, std::ios::beg);

                std::vector<char> content(size);
                if (file.read(content.data(), size)) {
                    return pw::HTTPResponse("200", std::move(content), {{"Content-Type", pw::filename_to_mimetype(filename)}});
                } else {
                    return pw::HTTPResponse::create_basic("500");
                }
            },
            true});

    if (server.bind("0.0.0.0", port) == PW_ERROR) {
        std::cerr << "Error: " << pw::universal_strerror() << std::endl;
        return 1;
    }

    std::cout << "Serving HTTP on 0.0.0.0 port " << port << " (http://0.0.0.0:" << port << "/) ..." << std::endl;
    if (server.listen() == PW_ERROR) {
        std::cerr << "Error: " << pw::universal_strerror() << std::endl;
        return 1;
    }

    pn::quit();
    return 0;
}
