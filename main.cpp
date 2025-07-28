#include "Polyweb/mimetypes.hpp"
#include "Polyweb/polyweb.hpp"
#include <algorithm>
#include <boost/program_options.hpp>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <string.h>
#include <string>
#include <time.h>
#include <vector>

#define CACHE_CONTROL_HEADER \
    {"Cache-Control", "public, no-cache"}
#define ACCESS_CONTROL_ALLOW_ORIGIN_HEADER \
    {"Access-Control-Allow-Origin", "*"}
#define BASE_HEADERS CACHE_CONTROL_HEADER, \
                     ACCESS_CONTROL_ALLOW_ORIGIN_HEADER

namespace po = boost::program_options;

typedef std::shared_mutex Lock;
typedef std::unique_lock<Lock> WriteLock;
typedef std::shared_lock<Lock> ReadLock;

struct CacheEntry {
    time_t last_modified;
    std::vector<char> content;
};

void configure_socket(pn::Socket& socket) {
#ifdef _WIN32
    DWORD send_timeout = 60'000;
    DWORD recv_timeout = 60'000;
#else
    struct timeval send_timeout;
    send_timeout.tv_sec = 60;
    send_timeout.tv_usec = 0;
    struct timeval recv_timeout;
    recv_timeout.tv_sec = 60;
    recv_timeout.tv_usec = 0;
#endif
    socket.setsockopt(SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof send_timeout);
    socket.setsockopt(SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof recv_timeout);

    int tcp_keep_alive = 1;
    socket.setsockopt(SOL_SOCKET, SO_KEEPALIVE, &tcp_keep_alive, sizeof(int));
}

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

pw::HTTPResponse make_error_resp(uint16_t status_code, const pw::HTTPHeaders& headers) {
    pw::HTTPResponse resp = make_error_resp(status_code);
    for (const auto& header : headers) {
        if (!resp.headers.count(header.first)) {
            resp.headers.insert(header);
        }
    }
    return resp;
}

void print_help(po::options_description& desc, char* prog_name) {
    std::cout << "Usage: " << prog_name << " [options] [port]\n\n"
              << desc;
}

int main(int argc, char* argv[]) {
    po::options_description desc("Options");
    po::positional_options_description p;
    po::variables_map vm;

    std::string port;
    std::string bind_address;
    std::filesystem::path root_dir_path;
    std::string certificate_chain_file;
    std::string private_key_file;

    // clang-format off
    desc.add_options()
        ("help,h", "Show this help message and exit")
        ("port,p", po::value(&port)->default_value("8000"), "Specify alternate port")
        ("bind,b", po::value(&bind_address)->default_value("0.0.0.0"), "Specify alternate bind address")
        ("directory,d", po::value(&root_dir_path)->default_value("."), "Specify alternative directory")
        ("certificate-chain-file,c", po::value(&certificate_chain_file), "Specify certificate chain file, enabling TLS")
        ("private-key-file,k", po::value(&private_key_file), "Specify private key file, enabling TLS");
    // clang-format on
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
    pn::UniqueSocket<pw::SecureServer> server;
    std::unordered_map<std::string, CacheEntry> cache;
    Lock cache_lock;

    server->on_error = (pw::HTTPResponse (*)(uint16_t)) &make_error_resp;

    server->route("/",
        pw::SecureHTTPRoute {
            [&root_dir_path, &cache, &cache_lock](const pw::SecureConnection& conn, const pw::HTTPRequest& req, void*) {
                std::cout << '[' << pw::build_date() << "] " << sockaddr_to_string(&conn.addr) << " - \"" << req.method << ' ' << req.target << ' ' << req.http_version << "\"" << std::endl;

                if (req.method != "GET" && req.method != "HEAD") {
                    return make_error_resp(405, {{"Allow", "GET, HEAD"}});
                }

                std::string relative_target = req.target;
                relative_target.erase(relative_target.begin(), std::find_if_not(relative_target.begin(), relative_target.end(), [](char c) {
                    return c == '/';
                }));

                std::vector<std::string> split_target = pw::string::split(relative_target, '/');
                for (const auto& component : split_target) {
                    if (component == "..") {
                        return make_error_resp(400);
                    }
                }

                auto path = root_dir_path / std::filesystem::path(relative_target);
                if (!std::filesystem::exists(path)) {
                    return make_error_resp(404);
                }

                if (std::filesystem::is_directory(path)) {
                    if (!relative_target.empty() && relative_target.back() != '/') {
                        return make_error_resp(301, {{"Location", '/' + relative_target + '/'}});
                    }

                    std::set<std::string> entries;
                    bool index_found = false;
                    for (const auto& entry : std::filesystem::directory_iterator(path)) {
                        auto entry_path = entry.path();
                        auto entry_filename = entry_path.filename();
                        if (entry_filename == "index.htm" || entry_filename == "index.html") {
                            path = entry_path;
                            index_found = true;
                            break;
                        }
                        entries.insert(entry_filename.generic_string());
                    }

                    if (!index_found) {
                        std::ostringstream ss;
                        ss << "<!DOCTYPE html>";
                        ss << "<html>";
                        ss << "<head>";
                        ss << "<meta http-equiv=\"Content-Type\" content=\"text/html\">";
                        ss << "<title>Directory listing for " << pw::xml_escape('/' + relative_target) << "</title>";
                        ss << "</head>";
                        ss << "<body>";
                        ss << "<h1>Directory listing for " << pw::xml_escape('/' + relative_target) << "</h1>";
                        ss << "<hr><ul>";
                        for (const auto& entry : entries) {
                            if (std::filesystem::is_directory(path / entry)) {
                                ss << "<li><a href=\"" << pw::xml_escape(entry) << "/\">" << pw::xml_escape(entry) << "/</a></li>";
                            } else {
                                ss << "<li><a href=\"" << pw::xml_escape(entry) << "\">" << pw::xml_escape(entry) << "</a></li>";
                            }
                        }
                        ss << "</ul><hr>";
                        ss << "</body>";
                        ss << "</html>";
                        ss << std::endl;
                        return pw::HTTPResponse(200, ss.str(), {{"Content-Type", "text/html"}, BASE_HEADERS});
                    }
                }

                time_t last_modified = std::chrono::system_clock::to_time_t(std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                    std::filesystem::last_write_time(path) - std::filesystem::file_time_type::clock::now() +
                    std::chrono::system_clock::now()));

                if (auto if_modified_since_it = req.headers.find("If-Modified-Since"); if_modified_since_it != req.headers.end() && pw::parse_date(if_modified_since_it->second) == last_modified) {
                    return pw::HTTPResponse(304, {BASE_HEADERS});
                }

                ReadLock r_lock(cache_lock);
                if (auto cache_entry_it = cache.find(path.generic_string()); cache_entry_it != cache.end() && cache_entry_it->second.last_modified == last_modified) {
                    return pw::HTTPResponse(200, cache_entry_it->second.content, {{"Content-Type", pw::filename_to_mimetype(path.string())}, {"Last-Modified", pw::build_date(last_modified)}, BASE_HEADERS});
                }
                r_lock.unlock();

                std::ifstream file(path, std::ifstream::binary | std::ifstream::ate);
                if (!file.is_open()) {
                    return make_error_resp(500, {BASE_HEADERS});
                }

                std::streamsize size = file.tellg();
                file.seekg(0, std::ifstream::beg);

                std::vector<char> content(size);
                if (file.read(content.data(), size)) {
                    WriteLock w_lock(cache_lock);
                    cache[path.generic_string()] = CacheEntry {
                        .last_modified = last_modified,
                        .content = content,
                    };
                    w_lock.unlock();
                    return pw::HTTPResponse(200, std::move(content), {{"Content-Type", pw::filename_to_mimetype(path.string())}, {"Last-Modified", pw::build_date(last_modified)}, BASE_HEADERS});
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

    if (!certificate_chain_file.empty() && !private_key_file.empty()) {
        if (server->ssl_init(certificate_chain_file, private_key_file, SSL_FILETYPE_PEM) == PN_ERROR) {
            std::cerr << "Error: " << pn::universal_strerror() << std::endl;
            return 1;
        }
        std::cout << "Serving HTTPS on " << bind_address << " port " << port << " (https://" << bind_address << ':' << port << "/) ..." << std::endl;
    } else {
        std::cout << "Serving HTTP on " << bind_address << " port " << port << " (http://" << bind_address << ':' << port << "/) ..." << std::endl;
    }

    if (server->listen([](pn::tcp::SecureConnection& conn, void*) {
            configure_socket(conn);
            return false;
        }) == PN_ERROR) {
        std::cerr << "Error: " << pw::universal_strerror() << std::endl;
        return 1;
    }

    pn::quit();
    return 0;
}
