#ifndef USER_H
#define USER_H

#include <string>

/*
This class represents a user in the chat room.
It should handle user authorization (username and password)
    and interaction with the chat room.
*/
class User
{
public:
    // Default constructor
    User();

    // Constructor with username and password
    User(const std::string& name, const std::string& password);

    // Getters for user properties
    std::string get_username() const;
    std::string get_password() const;

    // Setters for user properties
    void set_username(std::string& new_username);
    void set_password(std::string& new_password);

private:
    std::string username;
    std::string password;
};

#endif // !USER_H