#include "Message.h"
#include <iostream>

// Default constructor
Message::Message(/* args */)
{
    std::cout << "Message constructor()" << std::endl;
}

// Default destructor
Message::~Message()
{
    std::cout << "Message destructor()" << std::endl;
}