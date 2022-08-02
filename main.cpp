#include "Polyweb/mimetypes.hpp"
#include "Polyweb/polyweb.hpp"
#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <vector>

namespace po = boost::program_options;

struct CacheEntry {
    time_t last_modified;
    std::vector<char> content;
};

std::string sockaddr_to_string(const struct sockaddr* addr) {
    std::string ret;

    switch (addr->sa_family) {
        case AF_INET:
            pn::inet_ntop(AF_INET, &((struct sockaddr_in*) addr)->sin_addr, ret);
            break;

        case AF_INET6:
            pn::inet_ntop(AF_INET6, &((struct sockaddr_in6*) addr)->sin6_addr, ret);
            break;

        default:
            return "Unknown AF";
    }

    return ret;
}

pw::HTTPResponse create_error_resp(const std::string& status_code) {
    std::stringstream ss;
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
    return pw::HTTPResponse(status_code, ss.str(), {{"Content-Type", "text/html"}});
}

pw::HTTPResponse create_error_resp(const std::string& status_code, const pw::HTTPHeaders& headers) {
    pw::HTTPResponse resp = create_error_resp(status_code);
    for (auto& header : headers) {
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
    pw::Server server;
    std::unordered_map<std::string, CacheEntry> cache;

    server.on_error = (pw::HTTPResponse(*)(const std::string&)) & create_error_resp;

    server.route("/",
        pw::HTTPRoute {
            [&root_dir_path, &cache](const pw::Connection& conn, const pw::HTTPRequest& req) -> pw::HTTPResponse {
                std::cout << '[' << pw::build_date() << "] " << sockaddr_to_string(&conn.addr) << " - \"" << req.method << ' ' << req.target << ' ' << req.http_version << "\"" << std::endl;

                if (req.method != "GET") {
                    return create_error_resp("405", {{"Allow", "GET"}});
                }

                std::vector<std::string> split_req_target;
                boost::split(split_req_target, req.target, boost::is_any_of("/"));
                for (const auto& component : split_req_target) {
                    if (component == "..") {
                        return create_error_resp("400");
                    }
                }

                std::string filename = root_dir_path + req.target;

                struct stat s;
                if (stat(filename.c_str(), &s) == -1) {
                    if (errno == ENOENT || errno == ENOTDIR) {
                        return create_error_resp("404");
                    } else {
                        std::cerr << "Error: stat failed: " << strerror(errno) << std::endl;
                        return create_error_resp("500");
                    }
                }

                if (S_ISDIR(s.st_mode)) {
                    if (req.target.back() != '/') {
                        return create_error_resp("301", {{"Location", req.target + '/'}});
                    }

                    DIR* dir;
                    if ((dir = opendir(filename.c_str())) == NULL) {
                        std::cerr << "Error: opendir failed: " << strerror(errno) << std::endl;
                        return create_error_resp("500");
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
                            break;
                        }

                        entries.insert(std::move(string_entry_name));
                    }

                    closedir(dir);

                    if (!index_found) {
                        std::stringstream ss;
                        ss << "<!DOCTYPE html>";
                        ss << "<html>";
                        ss << "<head>";
                        ss << "<meta http-equiv=\"Content-Type\" content=\"text/html\">";
                        ss << "<title>Directory listing for " << req.target << "</title>";
                        ss << "</head>";
                        ss << "<body>";
                        ss << "<h1>Directory listing for " << req.target << "</h1>";
                        ss << "<hr><ul>";
                        for (const auto& entry : entries) {
                            struct stat s;
                            if (stat((filename + entry).c_str(), &s) == -1) {
                                std::cerr << "Error: stat failed: " << strerror(errno) << std::endl;
                                continue;
                            }
                            if (S_ISDIR(s.st_mode))
                                ss << "<li><a href=\"" << entry << "/\">" << entry << "/</a></li>";
                            else
                                ss << "<li><a href=\"" << entry << "\">" << entry << "</a></li>";
                        }
                        ss << "</ul><hr>";
                        ss << "</body>";
                        ss << "</html>";
                        ss << std::endl;
                        return pw::HTTPResponse("200", ss.str(), {{"Content-Type", "text/html"}});
                    }
                }

                decltype(cache)::const_iterator cache_entry_it;
                if ((cache_entry_it = cache.find(filename)) != cache.end()) {
                    pw::HTTPHeaders::const_iterator if_modified_since_it;
                    if ((if_modified_since_it = req.headers.find("If-Modified-Since")) != req.headers.end() && pw::parse_date(if_modified_since_it->second) == s.st_mtime) {
                        return pw::HTTPResponse::create_basic("304");
                    } else if (cache_entry_it->second.last_modified == s.st_mtime) {
                        return pw::HTTPResponse("200", cache_entry_it->second.content, {{"Content-Type", pw::filename_to_mimetype(filename)}, {"Last-Modified", pw::build_date(s.st_mtime)}});
                    }
                }

                std::ifstream file(filename, std::ios::binary | std::ios::ate);
                if (!file.is_open()) {
                    return create_error_resp("500");
                }

                std::streamsize size = file.tellg();
                file.seekg(0, std::ios::beg);

                std::vector<char> content(size);
                if (file.read(content.data(), size)) {
                    cache[filename] = CacheEntry {
                        .last_modified = s.st_mtime,
                        .content = content,
                    };
                    return pw::HTTPResponse("200", std::move(content), {{"Content-Type", pw::filename_to_mimetype(filename)}, {"Last-Modified", pw::build_date(s.st_mtime)}});
                } else {
                    return create_error_resp("500");
                }
            },
            true,
        });

    if (server.bind(bind_address, port) == PW_ERROR) {
        std::cerr << "Error: " << pw::universal_strerror() << std::endl;
        return 1;
    }

    std::cout << "Serving HTTP on " << bind_address << " port " << port << " (http://" << bind_address << ':' << port << "/) ..." << std::endl;
    if (server.listen() == PW_ERROR) {
        std::cerr << "Error: " << pw::universal_strerror() << std::endl;
        return 1;
    }

    pn::quit();
    return 0;
}
