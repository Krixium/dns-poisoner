#include "Config.h"

#include <fstream>
#include <sstream>

using std::unordered_map<std::string, std::string> = Properties

Properties getConfig(const std::string& config_filename) {
    std::ifstream file(config_filename);
    std::string line;
    Properties properties;

    if (file.is_open()) {
        while (std::getline(file, line)) {
            std::istringstream is_line(line);
            std::string key;
            if (std::getline(is_line, key, '=')) {
                std::string value;
                if (key[0] == '#') {
                    continue;
                }
                if (std::getline(is_line, value)) {
                    properties[key] = value;
                }
            }
        }
    }
    return properties;
}

Properties  getDomainNameIpPairs(const std::string& dns_filename) {
	Properties props;

}
