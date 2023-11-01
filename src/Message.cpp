#include "Message.h"
#include <iostream>
#include <sstream>
#include <iomanip>

// Default constructor
Message::Message(
    const std::string& content,
    const std::string& sender
)
    : content(content), sender(sender), timestamp(std::chrono::system_clock::now())
{
    // // validate the message
    // size_t content_size = content.size();
    // bool apt_size = (0 < content_size) && (content_size <= 64);
    // bool apt_chars = true;
    // for (size_t i = 0; i < content_size; ++i)
    // {
    //     if (content[i] < 32 || content[i] > 126)
    //     {
    //         apt_chars = false;
    //         break;
    //     }
    // }
    // bool apt_end = content[content_size - 1] == '.'
    //     || content[content_size - 1] == '?'
    //     || content[content_size - 1] == '!';
    // valid = apt_size && apt_chars && apt_end;
}

// Getters for message properties
std::string Message::get_sender() const
{
    return sender;
}
std::string Message::get_content() const
{
    return content;
}
std::chrono::system_clock::time_point Message::get_timestamp() const
{
    return timestamp;
}

std::string Message::to_string() const
{
    // return timestamp + " " + sender + ": " + content;
        // Convert the timestamp to a string in the desired format
    std::time_t timestamp_time = std::chrono::system_clock::to_time_t(timestamp);
    std::tm* timestamp_tm = std::localtime(&timestamp_time);

    // Format the timestamp as "HH:MM:SS"
    std::stringstream timestamp_str;
    timestamp_str << std::put_time(timestamp_tm, "%T");

    return timestamp_str.str() + " [" + sender + "]: " + content;
}

// Setters for message properties
void Message::set_sender(const std::string& sender)
{
    this->sender = sender;
}
void Message::set_content(const std::string& content)
{
    this->content = content;
}

// Default destructor
Message::~Message()
{
    // std::cout << "Message destructor()" << std::endl;
}