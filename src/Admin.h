// Admin.h
#ifndef ADMIN_H
#define ADMIN_H

#include "User.h"

class Admin : public User {
public:
    Admin(int id, const std::string &username, const std::string &email = "");
    std::string getInfo() const override;
    std::string toJson() const override;
};

#endif // ADMIN_H

