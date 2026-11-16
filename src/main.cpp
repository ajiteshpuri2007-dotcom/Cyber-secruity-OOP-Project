#include <iostream>
#include <memory>
#include "PhishingDetector.h"
#include "ScanResult.h"
#include "User.h"
#include "Admin.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: privy_engine <url> | privy_engine --test-oop\n";
        return 1;
    }

    std::string arg1 = argv[1];

    if (arg1 == "--test-oop") {
        // Demonstrate OOP classes: User, Admin, Polymorphism, Composition
        std::unique_ptr<User> normalUser = std::make_unique<User>(1, "standard_user", "user", "user@privy.local");
        std::unique_ptr<User> adminUser = std::make_unique<Admin>(2, "admin_user", "admin@privy.local");

        PhishingDetector demoDetector("https://safe-example.org");
        ScanResult demoResult = demoDetector.detect();

        std::cout << "{"
                  << "\"status\":\"ok\","
                  << "\"engine\":\"PRiVY C++ OOP Detection Engine\","
                  << "\"oop_validation\":{"
                  << "\"polymorphic_user_info\":\"" << normalUser->getInfo() << "\","
                  << "\"polymorphic_admin_info\":\"" << adminUser->getInfo() << "\","
                  << "\"user_json\":" << normalUser->toJson() << ","
                  << "\"admin_json\":" << adminUser->toJson() << ","
                  << "\"detector_sample\":" << demoResult.toJson()
                  << "}"
                  << "}" << std::endl;
        return 0;
    }

    std::string url = arg1;
    PhishingDetector detector(url);
    ScanResult result = detector.detect();

    // Member function serialization with strict escaping
    std::cout << result.toJson() << std::endl;
    return 0;
}


