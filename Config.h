#ifndef CONFIG_H
#define CONFIG_H

#include <unordered_map>
#include "main.h"

std::unordered_map<std::string, std::string> getConfig(const std::string& config_filename);
std::unordered_map<std::string, std::string> getDomainNameIpPairs(const std::string& config_filename);

std::vector<struct DomainIpPair> convertToVector(const std::unordered_map<std::string, std::string>& domainIpPairs);

#endif
