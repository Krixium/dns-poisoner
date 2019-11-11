#include "Config.h"

#include <fstream>
#include <sstream>
#include <iostream>
#include <arpa/inet.h>

using Properties = std::unordered_map<std::string, std::string>;

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

std::vector<struct DomainIpPair> convertToVector(const Properties& domainIpPairs) {
	std::vector<struct DomainIpPair> result;

	for (const auto& it : domainIpPairs) {
		struct DomainIpPair temp;
		// Convert the domain name into qname format
		strcpy((char*)temp.name, it.first.c_str());
		int err = inet_pton(AF_INET, it.second.c_str(), &temp.ip);
		if (err <= 0) {
			if (err == 0) {
				std::cerr << it.second << " is not in a valid format\n";
			} else {
				perror("inet_pton");
			}
		}
		result.push_back(temp);
	}
	return result;
}
