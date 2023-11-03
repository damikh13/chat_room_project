#ifndef CONFIGPARSER_H
#define CONFIGPARSER_H

#include <string>
#include <iostream>
#include <fstream>
#include <map>
#include "Logger.h"

class ConfigParser
{
public:
    // CONSTRUCTOR AND DESTRUCTOR
    ConfigParser(const std::string& config_file_path, Logger& logger);  // Default constructor
    ~ConfigParser();                                    // Default destructor

    // HELPER FUNCTIONS
    int get_int(const std::string& key);            // Get integer value from config file
    std::string get_string(const std::string& key); // Get string value from config file

private:
    std::string filename_;                      // Path to config file
    std::map<std::string, std::string> config_; // Map to store key-value pairs

    void read_config_file(Logger& logger); // Read config file and store key-value pairs in map
};

#endif // !CONFIGPARSER_H