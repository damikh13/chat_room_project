#ifndef MESSAGE_H
#define MESSAGE_H

#include <string>
#include <chrono>

/*
A class to represent chat messages, including
    * message content
    * sender
    * timestamp
*/
class Message
{
public:
    // Default constructor
    Message(
        const std::string& content,
        const std::string& sender
    );

    // Getters for message properties
    std::string get_sender() const;
    std::string get_content() const;
    std::chrono::system_clock::time_point get_timestamp() const;

    // Setters for message properties
    void set_sender(const std::string& sender);
    void set_content(const std::string& content);

    std::string to_string() const;

    ~Message();
private:
    std::string sender;
    std::string content;
    // std::string timestamp;
    std::chrono::system_clock::time_point timestamp;
};

#endif // !MESSAGE_H