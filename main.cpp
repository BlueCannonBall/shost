#include "Polyweb/mimetypes.hpp"
#include "Polyweb/polyweb.hpp"
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <signal.h>
#include <sstream>
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
                        std::cerr << "Error: stat failed: " << strerror(errno) << std::endl;
                        return pw::HTTPResponse::create_basic("500");
                    }
                }

                if (S_ISDIR(s.st_mode)) {
                    DIR* dir;
                    if ((dir = opendir(filename.c_str())) == NULL) {
                        std::cerr << "Error: opendir failed: " << strerror(errno) << std::endl;
                        return pw::HTTPResponse::create_basic("500");
                    }

                    struct dirent* entry;
                    std::vector<struct dirent> entries;
                    bool index_found = false;
                    while ((entry = readdir(dir))) {
                        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                            continue;

                        if (strcmp(entry->d_name, "index.htm") == 0 || strcmp(entry->d_name, "index.html") == 0) {
                            index_found = true;
                            filename += (filename.back() == '/' ? std::string() : "/") + entry->d_name;
                            break;
                        }

                        entries.push_back(*entry);
                    }

                    closedir(dir);

                    if (!index_found) {
                        std::stringstream ss;
                        ss << "<!DOCTYPE html>";
                        ss << "<html>";
                        ss << "<head>";
                        ss << "<meta http-equiv=\"Content-Type\" content=\"text/html\">";
                        ss << "<title>Directory listing for " << req.target << (req.target.size() > 1 ? "/</title>" : "</title>");
                        ss << "</head>";
                        ss << "<body>";
                        ss << "<h1>Directory listing for " << req.target << (req.target.size() > 1 ? "/</h1>" : "</h1>");
                        ss << "<hr><ul>";
                        for (const auto& entry : entries) {
                            std::string full_path = (filename.back() == '/' ? filename : filename + "/") + entry.d_name;
                            struct stat s;
                            if (stat(full_path.c_str(), &s) == -1) {
                                std::cerr << "Error: stat failed: " << strerror(errno) << std::endl;
                                continue;
                            }
                            ss << "<li><a href=\"" << full_path.substr(1) << "\">" << entry.d_name << (S_ISDIR(s.st_mode) ? "/</a></li>" : "</a></li>");
                        }
                        ss << "</ul><hr>";
                        ss << "</body>";
                        ss << "</html>";
                        return pw::HTTPResponse("200", ss.str(), {{"Content-Type", "text/html"}});
                    }
                }

                std::ifstream file(filename, std::ios::binary | std::ios::ate);
                if (!file.is_open()) {
                    return pw::HTTPResponse::create_basic("500");
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
