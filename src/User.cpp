// User.cpp
#include "User.h"
#include <sstream>

User::User(int id, const std::string &username, const std::string &role, const std::string &email)
    : id(id), username(username), role(role), email(email) {}

int User::getId() const { return id; }
const std::string& User::getUsername() const { return username; }
const std::string& User::getRole() const { return role; }
const std::string& User::getEmail() const { return email; }

void User::setEmail(const std::string &em) { email = em; }

std::string User::getInfo() const {
    return "User[ID=" + std::to_string(id) + ", Username=" + username + ", Role=" + role + "]";
}

std::string User::toJson() const {
    std::ostringstream ss;
    ss << "{\"id\":" << id << ",\"username\":\"" << username << "\",\"role\":\"" << role << "\",\"email\":\"" << email << "\"}";
    return ss.str();
}


