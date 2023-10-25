#include "Message.h"
#include <iostream>

// Default constructor
Message::Message(
    const std::string& content,
    const std::string& sender,
    const std::string& timestamp,
    bool valid
)
    : content(content), sender(sender), timestamp(timestamp), valid(valid)
{
    // validate the message
    size_t content_size = content.size();
    bool apt_size = (0 < content_size) && (content_size <= 64);
    bool apt_chars = true;
    for (size_t i = 0; i < content_size; ++i)
    {
        if (content[i] < 32 || content[i] > 126)
        {
            apt_chars = false;
            break;
        }
    }
    bool apt_end = content[content_size - 1] == '.'
        || content[content_size - 1] == '?'
        || content[content_size - 1] == '!';
    valid = apt_size && apt_chars && apt_end;
}

// Default destructor
Message::~Message()
{
    std::cout << "Message destructor()" << std::endl;
}