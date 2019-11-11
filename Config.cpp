#include "Config.h"

#include <arpa/inet.h>
#include <fstream>
#include <iostream>
#include <sstream>

using Properties = std::unordered_map<std::string, std::string>;

int stringToDnsDomain(const std::string& src, unsigned char* output) {
    unsigned char blockHead = 0;
    unsigned char blockSize = 0;
    unsigned char outputBaseIndex = 0;

    int i;
    for (i = 0; src[i]; i++) {
        if (src[i] == '.') {
            // calculate block size and place it as first character in output
            blockSize = i - blockHead;
            output[outputBaseIndex] = blockSize;
            outputBaseIndex++;

            // copy block
            for (int j = 0; j < blockSize; j++) {
                output[outputBaseIndex + j] = src[blockHead + j];
            }
            outputBaseIndex += blockSize;

            // adjust block head to next block
            blockHead = i + 1;
        }
    }

    // calculate block size and place it as first character in output
    blockSize = i - blockHead;
    output[outputBaseIndex] = blockSize;
    outputBaseIndex++;

    // copy block
    for (int j = 0; j < blockSize; j++) {
        output[outputBaseIndex + j] = src[blockHead + j];
    }

    outputBaseIndex += blockSize;

    // place last null byte
    output[outputBaseIndex] = 0;

    return outputBaseIndex + 1;
}

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
        if (it.first.size() > 255) {
            std::cerr << "domain name is too long: " << it.first << std::endl;
            continue;
        }

        stringToDnsDomain(it.first.c_str(), temp.name);

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
