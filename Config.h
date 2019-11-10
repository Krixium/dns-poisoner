#ifndef CONFIG_H
#define CONFIG_H

#include <unordered_map>

std::unordered_map<std::string, std::string> getConfig(const std::string& config_filename);

#endif