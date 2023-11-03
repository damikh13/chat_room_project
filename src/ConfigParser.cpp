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
        bool needs_to_be_skipped = (line.empty() || line[0] == '#');
        if (needs_to_be_skipped)
        {
            continue;
        }

        size_t delimiter_pos = line.find('=');
        bool has_delimiter = (delimiter_pos != std::string::npos);
        if (has_delimiter)
        {
            std::string key = line.substr(0, delimiter_pos - 1);
            std::string value = line.substr(delimiter_pos + 2);
            config_[key] = value;
            logger.log(Logger::log_level::DEBUG, "Read key-value pair: [" + key + "][" + value + "]");
        }
    }

    logger.log(Logger::log_level::DEBUG, "...Finished reading config file");
}