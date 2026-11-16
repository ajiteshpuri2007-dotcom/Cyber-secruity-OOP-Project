// Admin.cpp
#include "Admin.h"
#include <sstream>

Admin::Admin(int id, const std::string &username, const std::string &email)
    : User(id, username, "admin", email) {}

std::string Admin::getInfo() const {
    return "Admin[ID=" + std::to_string(getId()) + ", Username=" + getUsername() + ", Role=admin]";
}

std::string Admin::toJson() const {
    std::ostringstream ss;
    ss << "{\"id\":" << getId() << ",\"username\":\"" << getUsername() << "\",\"role\":\"admin\",\"email\":\"" << getEmail() << "\",\"permissions\":[\"manage_users\",\"view_all_scans\",\"system_stats\"]}";
    return ss.str();
}


