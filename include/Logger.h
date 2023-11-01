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

    Logger(const std::string& file_path, log_level logLevel = log_level::INFO);
    ~Logger();

    static void set_log_level(log_level level);
    void log(log_level level, const std::string& message);

    static std::string get_current_time();
private:
    static log_level current_log_level;
    std::ofstream log_file;

    std::map<log_level, std::string> log_level_to_string = {
        {log_level::DEBUG, "DEBUG"},
        {log_level::INFO, "INFO"},
        {log_level::WARNING, "WARNING"},
        {log_level::ERROR, "ERROR"}
    };
};

#endif