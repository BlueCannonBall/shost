#include "Polyweb/mimetypes.hpp"
#include "Polyweb/polyweb.hpp"
#include <algorithm>
#include <boost/program_options.hpp>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <stdlib.h>
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

std::string sockaddr_to_string(const struct sockaddr_storage& addr) {
    std::string ret;
    switch (addr.ss_family) {
    case AF_INET: {
        struct sockaddr_in inet_addr;
        memcpy(&inet_addr, &addr, sizeof inet_addr);
        if (!pn::inet_ntop(AF_INET, &inet_addr.sin_addr, ret)) {
            return "Unknown address";
        }
        break;
    }

    case AF_INET6: {
        struct sockaddr_in6 inet6_addr;
        memcpy(&inet6_addr, &addr, sizeof inet6_addr);
        if (!pn::inet_ntop(AF_INET6, &inet6_addr.sin6_addr, ret)) {
            return "Unknown address";
        }
        break;
    }

    default:
        return "Unknown address family";
    }
    return ret;
}

pw::Response make_error_resp(uint16_t status_code, pn::StringView what = {}) {
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
    if (!what.empty()) {
        ss << "<p>Error message: " << what << "</p>";
    }
    ss << "<p>Message: " << pw::status_code_to_reason_phrase(status_code) << "</p>";
    ss << "</body>";
    ss << "</html>";
    ss << std::endl;
    return pw::Response(status_code, ss.str(), {{"Content-Type", "text/html"}, BASE_HEADERS});
}

pw::Response make_error_resp(uint16_t status_code, const pw::Headers& headers) {
    pw::Response resp = make_error_resp(status_code);
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
    bool quiet;

    // clang-format off
    desc.add_options()
        ("help,h", "Show this help message and exit")
        ("port,p", po::value(&port)->default_value("8000"), "Specify alternate port")
        ("bind,b", po::value(&bind_address)->default_value("0.0.0.0"), "Specify alternate bind address")
        ("directory,d", po::value(&root_dir_path)->default_value("."), "Specify alternative directory")
        ("certificate-chain-file,c", po::value(&certificate_chain_file), "Specify certificate chain file, enabling TLS")
        ("private-key-file,k", po::value(&private_key_file), "Specify private key file, enabling TLS")
        ("quiet,q", po::bool_switch(&quiet), "Suppress access logs");
    // clang-format on
    p.add("port", 1);

    try {
        po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
        po::notify(vm);

        if (vm.count("help")) {
            print_help(desc, argv[0]);
            return EXIT_SUCCESS;
        }

        root_dir_path = std::filesystem::canonical(root_dir_path);
    } catch (std::exception& e) {
        if (vm.count("help")) {
            print_help(desc, argv[0]);
            return EXIT_SUCCESS;
        } else {
            std::cerr << "Error: CLI error: " << e.what() << std::endl;
            return EXIT_FAILURE;
        }
    }

    if (pn::Status result = pn::init(true); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return EXIT_FAILURE;
    }

    pw::TLSServer server;
    std::unordered_map<std::string, CacheEntry> cache;
    Lock cache_lock;

    server.config.tcp.send_timeout = std::chrono::seconds(60);
    server.config.tcp.recv_timeout = std::chrono::seconds(60);

    server.error_cb = [](uint16_t status_code, pn::StringView what) {
        return make_error_resp(status_code, what);
    };

    server.route("/",
        pw::TLSRoute {
            [&root_dir_path, &cache, &cache_lock, quiet](const pw::TLSConnection& conn, const pw::Request& req) {
                if (!quiet) {
                    std::cout << '[' << pw::build_date() << "] " << sockaddr_to_string(conn.addr) << " - \"" << req.method << ' ' << req.target << ' ' << req.http_version << "\"" << std::endl;
                }

                if (req.method != "GET" && req.method != "HEAD") {
                    return make_error_resp(405, {{"Allow", "GET, HEAD"}});
                }

                std::string relative_target = req.target;
                relative_target.erase(relative_target.begin(), std::find_if_not(relative_target.begin(), relative_target.end(), [](char c) {
                    return c == '/' || c == '\\';
                }));
                std::string target = '/' + relative_target;

                auto path = std::filesystem::weakly_canonical(root_dir_path / relative_target);
                if (std::mismatch(root_dir_path.begin(), root_dir_path.end(), path.begin(), path.end()).first != root_dir_path.end()) {
                    return make_error_resp(400);
                } else if (!std::filesystem::exists(path)) {
                    return make_error_resp(404);
                }

                if (std::filesystem::is_directory(path)) {
                    if (target.back() != '/') {
                        return make_error_resp(301, {{"Location", target + '/'}});
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
                        ss << "<title>Directory listing for " << pw::xml_escape(target) << "</title>";
                        ss << "</head>";
                        ss << "<body>";
                        ss << "<h1>Directory listing for " << pw::xml_escape(target) << "</h1>";
                        ss << "<hr><ul>";
                        for (const auto& entry : entries) {
                            if (std::filesystem::is_directory(path / entry)) {
                                ss << "<li><a href=\"./" << pw::xml_escape(entry) << "/\">" << pw::xml_escape(entry) << "/</a></li>";
                            } else {
                                ss << "<li><a href=\"./" << pw::xml_escape(entry) << "\">" << pw::xml_escape(entry) << "</a></li>";
                            }
                        }
                        ss << "</ul><hr>";
                        ss << "</body>";
                        ss << "</html>";
                        ss << std::endl;
                        return pw::Response(200, ss.str(), {{"Content-Type", "text/html"}, BASE_HEADERS});
                    }
                }

                time_t last_modified = std::chrono::system_clock::to_time_t(std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                    std::filesystem::last_write_time(path) - std::filesystem::file_time_type::clock::now() +
                    std::chrono::system_clock::now()));

                if (auto if_modified_since_it = req.headers.find("If-Modified-Since"); if_modified_since_it != req.headers.end() && pw::parse_date(if_modified_since_it->second) == last_modified) {
                    return pw::Response(304, {BASE_HEADERS});
                }

                ReadLock r_lock(cache_lock);
                if (auto cache_entry_it = cache.find(path.generic_string()); cache_entry_it != cache.end() && cache_entry_it->second.last_modified == last_modified) {
                    return pw::Response(200, cache_entry_it->second.content, {{"Content-Type", pw::filename_to_mimetype(path.string())}, {"Last-Modified", pw::build_date(last_modified)}, BASE_HEADERS});
                }
                r_lock.unlock();

                std::ifstream file(path, std::ifstream::binary | std::ifstream::ate);
                if (!file.is_open()) {
                    return make_error_resp(500, {BASE_HEADERS});
                }

                std::streamsize size = file.tellg();
                file.seekg(0, std::ifstream::beg);
                if (size > 1'000'000) {
                    return pw::Response(200, [file = std::make_shared<std::ifstream>(std::move(file))]() -> std::vector<char> {
                        if (file->good()) {
                            std::vector<char> data(1'000'000);
                            file->read(data.data(), data.size());
                            if (file->gcount() > 0) {
                                data.resize(file->gcount());
                                return data;
                            }
                        }
                        return {};
                    },
                        {{"Content-Type", pw::filename_to_mimetype(path.string())}, {"Last-Modified", pw::build_date(last_modified)}, BASE_HEADERS});
                }

                std::vector<char> content(size);
                if (file.read(content.data(), size)) {
                    WriteLock w_lock(cache_lock);
                    cache[path.generic_string()] = CacheEntry {
                        .last_modified = last_modified,
                        .content = content,
                    };
                    w_lock.unlock();
                    return pw::Response(200, std::move(content), {{"Content-Type", pw::filename_to_mimetype(path.string())}, {"Last-Modified", pw::build_date(last_modified)}, BASE_HEADERS});
                }
                return make_error_resp(500);
            },
            true,
        });

    if (pn::Status result = server.bind(bind_address, port); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return EXIT_FAILURE;
    }

    pn::TLSContext context;
    if (!certificate_chain_file.empty() && !private_key_file.empty()) {
        if (pn::Status result = context.init_server(certificate_chain_file, private_key_file, SSL_FILETYPE_PEM); !result) {
            std::cerr << "Error: " << result.error().message() << std::endl;
            return EXIT_FAILURE;
        }
        std::cout << "Serving HTTPS on " << bind_address << " port " << port << " (https://" << bind_address << ':' << port << "/) ..." << std::endl;
    } else {
        std::cout << "Serving HTTP on " << bind_address << " port " << port << " (http://" << bind_address << ':' << port << "/) ..." << std::endl;
    }

    if (pn::Status result = context ? server.listen(context) : server.listen(); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return EXIT_FAILURE;
    }

    (void) server.close();
    (void) pn::quit();
    return EXIT_SUCCESS;
}
