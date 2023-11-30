#include "ConfigParser.h"

// CONSTRUCTOR AND DESTRUCTOR
ConfigParser::ConfigParser(const std::string& config_file_path, Logger& logger) // Default constructor
    : filename_(config_file_path)
{
    read_config_file(logger);
}
ConfigParser::~ConfigParser()                                   // Default destructor
{
}

// HELPER FUNCTIONS
int ConfigParser::get_int(const std::string& key)               // Get integer value from config file
{
    return std::stoi(config_[key]);
}
std::string ConfigParser::get_string(const std::string& key)    // Get string value from config file
{
    return config_[key];
}

void ConfigParser::read_config_file(Logger& logger)
{
    logger.log(Logger::log_level::DEBUG, "Reading config file...");
    std::ifstream config_file(filename_);
    if (!config_file.is_open())
    {
        logger.log(Logger::log_level::ERROR, "Could not open config file: " + filename_);
        return;
    }

    std::string line;
    while (std::getline(config_file, line))
    {
        if (!line.empty() && line.back() == '\r')
        {
            line.pop_back();
        }

        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);

        // Skip empty lines and comments
        bool needs_to_be_skipped = line.empty() || line[0] == '#';
        if (needs_to_be_skipped)
        {
            continue;
        }

        // Find the delimiter position
        size_t delimiter_pos = line.find('=');
        if (delimiter_pos != std::string::npos && delimiter_pos > 0)
        {
            // Extract and trim key
            std::string key = line.substr(0, delimiter_pos);
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);

            // Extract and trim value
            std::string value = line.substr(delimiter_pos + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);

            // Store the key-value pair
            config_[key] = value;
            logger.log(Logger::log_level::DEBUG, "Read key-value pair: [" + key + "][" + value + "]");
        }
    }

    logger.log(Logger::log_level::DEBUG, "...Finished reading config file");
}