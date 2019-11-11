#ifndef CONFIG_H
#define CONFIG_H

#include "main.h"
#include <unordered_map>

int stringToDnsDomain(const std::string& src, unsigned char *output);

std::unordered_map<std::string, std::string> getConfig(const std::string& config_filename);

std::vector<struct DomainIpPair>
convertToVector(const std::unordered_map<std::string, std::string>& domainIpPairs);

#endif
