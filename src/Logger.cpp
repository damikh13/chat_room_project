#include "Logger.h"
#include <iostream>

// Default constructor
Logger::Logger(/* args */)
{
    std::cout << "Logger constructor()" << std::endl;
}

// Default destructor
Logger::~Logger()
{
    std::cout << "Logger destructor()" << std::endl;
}