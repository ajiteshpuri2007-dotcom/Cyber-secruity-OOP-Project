// User.h
#ifndef USER_H
#define USER_H

#include <string>

class User {
protected:
    int id;                // unique identifier
    std::string username;  // login name
    std::string role;      // "user" or "admin"
    std::string email;     // user email

public:
    User(int id, const std::string &username, const std::string &role, const std::string &email = "");
    virtual ~User() = default;

    int getId() const;
    const std::string& getUsername() const;
    const std::string& getRole() const;
    const std::string& getEmail() const;

    void setEmail(const std::string &em);

    // Polymorphic interface – overridden by Admin subclass
    virtual std::string getInfo() const;
    virtual std::string toJson() const;
};

#endif // USER_H

