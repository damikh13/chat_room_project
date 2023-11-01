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
