#include "Logger.h"
#include <iostream>

#include "Logger.h"

Logger::Logger(log_level logLevel, const std::string& name_of_who_is_logging)
{
    log_file.open("log.txt", std::ios_base::app);
    if (!log_file.is_open())
    {
        std::cerr << "Error opening log file" << std::endl;
    }
    log(log_level::INFO, "Logger started");
    current_log_level = logLevel;
    who_is_logging = name_of_who_is_logging;
}

Logger::~Logger()
{
    log(log_level::INFO, "Logger stopped");
    log_file.close();
}

void Logger::set_log_level(log_level level)
{
    current_log_level = level;
}

void Logger::log(log_level level, const std::string& message)
{
    // if (static_cast<int>(level) >= static_cast<int>(current_log_level))
    // {
    log_file
        << get_current_time()
        << " ["
        << log_level_to_string[level]
        << "] "
        << " by ["
        << who_is_logging
        << "]"
        << message
        << std::endl;
    // }
}

std::string Logger::get_current_time()
{
    std::time_t current_time = std::time(nullptr);
    char time_str[20];
    std::strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", std::localtime(&current_time));
    return time_str;
}

Logger::log_level Logger::current_log_level = Logger::log_level::INFO;
