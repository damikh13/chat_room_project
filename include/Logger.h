#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <string>
#include <fstream>
#include <ctime>
#include <map>

class Logger
{
public:
    enum class log_level
    {
        DEBUG,
        INFO,
        WARNING,
        ERROR
    };

    Logger(log_level logLevel = log_level::INFO, const std::string& who_is_logging = "unknown");
    ~Logger();

    static void set_log_level(log_level level);
    void log(log_level level, const std::string& message);

private:
    static log_level current_log_level;
    std::ofstream log_file;
    std::string who_is_logging;

    static std::string get_current_time();
    std::map<log_level, std::string> log_level_to_string = {
        {log_level::DEBUG, "DEBUG"},
        {log_level::INFO, "INFO"},
        {log_level::WARNING, "WARNING"},
        {log_level::ERROR, "ERROR"}
    };
};

#endif