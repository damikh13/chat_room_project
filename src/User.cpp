#include "User.h"

User::User() {}

User::User(const std::string& name, const std::string& password)
    : username(name), password(password) {}

std::string User::get_username() const
{
    return username;
}

std::string User::get_password() const
{
    return password;
}

void User::set_username(std::string& new_username)
{
    this->username = new_username;
}

void User::set_password(std::string& new_password)
{
    this->password = new_password;
}
