#include "tools/traceql/symbols/remote_symbol_resolver.h"

#include <fstream>
#include <sstream>

namespace traceql {

    RemoteSymbolResolver &RemoteSymbolResolver::instance() noexcept {
        static RemoteSymbolResolver s_instance;
        return s_instance;
    }

    void RemoteSymbolResolver::cacheResolution(std::string_view symbol, std::string_view library) {
        if (!symbol.empty() && !library.empty()) {
            cache_[std::string(symbol)] = std::string(library);
        }
    }

    std::string_view RemoteSymbolResolver::lookup(std::string_view symbol_name) const noexcept {
        auto it = cache_.find(std::string(symbol_name));
        if (it != cache_.end()) {
            return it->second;
        }
        return {};
    }

    size_t RemoteSymbolResolver::loadManifestFile(const std::string &manifest_path) {
        std::ifstream file(manifest_path);
        if (!file.is_open()) {
            return 0;
        }

        size_t count = 0;
        std::string line;
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') {
                continue;
            }
            std::istringstream iss(line);
            std::string symbol, library;
            if (iss >> symbol >> library) {
                cache_[symbol] = library;
                ++count;
            }
        }
        return count;
    }

    std::string RemoteSymbolResolver::formatOnlineLookupUrl(std::string_view symbol_name) const {
        std::string url = "https://www.google.com/search?q=";
        url += symbol_name;
        url += "+C+library+documentation";
        return url;
    }

} // namespace traceql
