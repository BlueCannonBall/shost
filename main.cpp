#include "Polyweb/mimetypes.hpp"
#include "Polyweb/polyweb.hpp"
#include <boost/program_options.hpp>
#include <boost/thread/locks.hpp>
#include <boost/thread/shared_mutex.hpp>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

#define CACHE_CONTROL_HEADER \
    { "Cache-Control", "public, no-cache" }
#define ACCESS_CONTROL_ALLOW_ORIGIN_HEADER \
    { "Access-Control-Allow-Origin", "*" }
#define CROSS_ORIGIN_OPENER_POLICY_HEADER \
    { "Cross-Origin-Opener-Policy", "same-origin" }
#define CROSS_ORIGIN_EMBEDDER_POLICY_HEADER \
    { "Cross-Origin-Embedder-Policy", "require-corp" }
#define BASE_HEADERS CACHE_CONTROL_HEADER,               \
                     ACCESS_CONTROL_ALLOW_ORIGIN_HEADER, \
                     CROSS_ORIGIN_OPENER_POLICY_HEADER,  \
                     CROSS_ORIGIN_EMBEDDER_POLICY_HEADER

namespace po = boost::program_options;

typedef boost::shared_mutex Lock;
typedef boost::unique_lock<Lock> WriteLock;
typedef boost::shared_lock<Lock> ReadLock;

struct CacheEntry {
    time_t last_modified;
    std::vector<char> content;
};

std::string sockaddr_to_string(const struct sockaddr* addr) {
    std::string ret;
    switch (addr->sa_family) {
    case AF_INET: {
        struct sockaddr_in inet_addr;
        memcpy(&inet_addr, addr, sizeof inet_addr);
        pn::inet_ntop(AF_INET, &inet_addr.sin_addr, ret);
        break;
    }

    case AF_INET6: {
        struct sockaddr_in6 inet6_addr;
        memcpy(&inet6_addr, addr, sizeof inet6_addr);
        pn::inet_ntop(AF_INET6, &inet6_addr.sin6_addr, ret);
        break;
    }

    default:
        return "Unknown address family";
    }
    return ret;
}

pw::HTTPResponse make_error_resp(uint16_t status_code) {
    std::ostringstream ss;
    ss << "<!DOCTYPE html>";
    ss << "<html>";
    ss << "<head>";
    ss << "<meta http-equiv=\"Content-Type\" content=\"text/html\">";
    ss << "<title>Error response</title>";
    ss << "</head>";
    ss << "<body>";
    ss << "<h1>Error response</h1>";
    ss << "<p>Error code: " << status_code << "</p>";
    ss << "<p>Message: " << pw::status_code_to_reason_phrase(status_code) << "</p>";
    ss << "</body>";
    ss << "</html>";
    ss << std::endl;
    return pw::HTTPResponse(status_code, ss.str(), {{"Content-Type", "text/html"}, BASE_HEADERS});
}

pw::HTTPResponse make_error_resp(uint16_t status_code, pw::HTTPHeaders headers) {
    pw::HTTPResponse resp = make_error_resp(status_code);
    for (const auto& header : headers) {
        if (!resp.headers.count(header.first)) {
            resp.headers.insert(std::move(header));
        }
    }
    return resp;
}

void print_help(po::options_description& desc, char* prog_name) {
    std::cout << "Usage: " << prog_name << " [options] [port]\n\n"
              << desc;
}

int main(int argc, char** argv) {
    po::options_description desc("Options");
    po::positional_options_description p;
    po::variables_map vm;

    std::string port;
    std::string bind_address;
    std::string root_dir_path;

    desc.add_options()("help,h", "Show this help message and exit")("port,p", po::value(&port)->default_value("8000"), "Specify alternate port")("bind,b", po::value(&bind_address)->default_value("0.0.0.0"), "Specify alternate bind address")("directory,d", po::value(&root_dir_path)->default_value("."), "Specify alternative directory");
    p.add("port", 1);

    try {
        po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
        po::notify(vm);

        if (vm.count("help")) {
            print_help(desc, argv[0]);
            return 0;
        }
    } catch (std::exception& e) {
        if (vm.count("help")) {
            print_help(desc, argv[0]);
            return 0;
        } else {
            std::cerr << "Error: CLI error: " << e.what() << std::endl;
            return 1;
        }
    }

    pn::init(true);
    pn::UniqueSock<pw::Server> server;
    std::unordered_map<std::string, CacheEntry> cache;
    Lock cache_lock;

    server->on_error = (pw::HTTPResponse(*)(uint16_t)) & make_error_resp;

    server->route("/",
        pw::HTTPRoute {
            [&root_dir_path, &cache, &cache_lock](const pw::Connection& conn, const pw::HTTPRequest& req, void*) {
                std::cout << '[' << pw::build_date() << "] " << sockaddr_to_string(&conn.addr) << " - \"" << req.method << ' ' << req.target << ' ' << req.http_version << "\"" << std::endl;

                if (req.method != "GET") {
                    return make_error_resp(405, {{"Allow", "GET"}});
                }

                std::vector<std::string> split_req_target = pw::string::split(req.target, '/');
                for (const auto& component : split_req_target) {
                    if (component == "..") {
                        return make_error_resp(400);
                    }
                }

                std::string filename = root_dir_path + req.target;

                struct stat s;
                if (stat(filename.c_str(), &s) == -1) {
                    if (errno == ENOENT || errno == ENOTDIR) {
                        return make_error_resp(404);
                    } else {
                        std::cerr << "Error: stat failed: " << strerror(errno) << std::endl;
                        return make_error_resp(500);
                    }
                }

                if (S_ISDIR(s.st_mode)) {
                    if (req.target.back() != '/') {
                        return make_error_resp(301, {{"Location", req.target + '/'}});
                    }

                    DIR* dir;
                    if ((dir = opendir(filename.c_str())) == NULL) {
                        std::cerr << "Error: opendir failed: " << strerror(errno) << std::endl;
                        return make_error_resp(500);
                    }

                    struct dirent* entry;
                    std::set<std::string> entries;
                    bool index_found = false;
                    while ((entry = readdir(dir))) {
                        std::string string_entry_name(entry->d_name);

                        if (string_entry_name == "." || string_entry_name == "..")
                            continue;

                        if (string_entry_name == "index.html" || string_entry_name == "index.htm") {
                            index_found = true;
                            filename += string_entry_name;
                            if (stat(filename.c_str(), &s) == -1) {
                                if (errno == ENOENT || errno == ENOTDIR) {
                                    return make_error_resp(404);
                                } else {
                                    std::cerr << "Error: stat failed: " << strerror(errno) << std::endl;
                                    return make_error_resp(500);
                                }
                            }
                            break;
                        }

                        entries.insert(std::move(string_entry_name));
                    }

                    closedir(dir);

                    if (!index_found) {
                        std::ostringstream ss;
                        ss << "<!DOCTYPE html>";
                        ss << "<html>";
                        ss << "<head>";
                        ss << "<meta http-equiv=\"Content-Type\" content=\"text/html\">";
                        ss << "<title>Directory listing for " << pw::escape_xml(req.target) << "</title>";
                        ss << "</head>";
                        ss << "<body>";
                        ss << "<h1>Directory listing for " << pw::escape_xml(req.target) << "</h1>";
                        ss << "<hr><ul>";
                        for (const auto& entry : entries) {
                            struct stat s;
                            if (stat((filename + entry).c_str(), &s) == -1) {
                                std::cerr << "Error: stat failed: " << strerror(errno) << std::endl;
                                continue;
                            }
                            if (S_ISDIR(s.st_mode))
                                ss << "<li><a href=\"" << pw::escape_xml(entry) << "/\">" << pw::escape_xml(entry) << "/</a></li>";
                            else
                                ss << "<li><a href=\"" << pw::escape_xml(entry) << "\">" << pw::escape_xml(entry) << "</a></li>";
                        }
                        ss << "</ul><hr>";
                        ss << "</body>";
                        ss << "</html>";
                        ss << std::endl;
                        return pw::HTTPResponse(200, ss.str(), {{"Content-Type", "text/html"}, BASE_HEADERS});
                    }
                }

                pw::HTTPHeaders::const_iterator if_modified_since_it;
                if ((if_modified_since_it = req.headers.find("If-Modified-Since")) != req.headers.end() && pw::parse_date(if_modified_since_it->second) == s.st_mtime) {
                    return pw::HTTPResponse(304, {BASE_HEADERS});
                }

                ReadLock r_lock(cache_lock);
                decltype(cache)::const_iterator cache_entry_it;
                if ((cache_entry_it = cache.find(filename)) != cache.end() && cache_entry_it->second.last_modified == s.st_mtime) {
                    return pw::HTTPResponse(200, cache_entry_it->second.content, {{"Content-Type", pw::filename_to_mimetype(filename)}, {"Last-Modified", pw::build_date(s.st_mtime)}, BASE_HEADERS});
                }
                r_lock.unlock();

                std::ifstream file(filename, std::ios::binary | std::ios::ate);
                if (!file.is_open()) {
                    return make_error_resp(500, {BASE_HEADERS});
                }

                std::streamsize size = file.tellg();
                file.seekg(0, std::ios::beg);

                std::vector<char> content(size);
                if (file.read(content.data(), size)) {
                    WriteLock w_lock(cache_lock);
                    cache[filename] = CacheEntry {
                        .last_modified = s.st_mtime,
                        .content = content,
                    };
                    w_lock.unlock();
                    return pw::HTTPResponse(200, std::move(content), {{"Content-Type", pw::filename_to_mimetype(filename)}, {"Last-Modified", pw::build_date(s.st_mtime)}, BASE_HEADERS});
                } else {
                    return make_error_resp(500);
                }
            },
            nullptr,
            true,
        });

    if (server->bind(bind_address, port) == PN_ERROR) {
        std::cerr << "Error: " << pn::universal_strerror() << std::endl;
        return 1;
    }

    std::cout << "Serving HTTP on " << bind_address << " port " << port << " (http://" << bind_address << ':' << port << "/) ..." << std::endl;
    if (server->listen() == PN_ERROR) {
        std::cerr << "Error: " << pw::universal_strerror() << std::endl;
        return 1;
    }

    pn::quit();
    return 0;
}
