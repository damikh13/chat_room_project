#ifndef MESSAGE_H
#define MESSAGE_H

#include <string>

/*
A class to represent chat messages, including
    * message content
    * sender
    * timestamp
    * validation.
*/
class Message
{
private:
    std::string content;
    std::string sender;
    std::string timestamp;
    bool valid;
public:
    Message(
        const std::string& content,
        const std::string& sender,
        const std::string& timestamp,
        bool valid
    );
    ~Message();
};

#endif // !MESSAGE_H