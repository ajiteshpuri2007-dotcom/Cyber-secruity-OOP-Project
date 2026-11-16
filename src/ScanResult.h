// ScanResult.h
#ifndef SCAN_RESULT_H
#define SCAN_RESULT_H

#include <string>
#include <vector>

class ScanResult {
private:
    std::string url;
    bool isPhishing;
    int securityScore;
    std::vector<std::string> reasons;

    static std::string escapeJson(const std::string &input);

public:
    ScanResult();
    ScanResult(const std::string &url, bool isPhishing, int securityScore, const std::vector<std::string> &reasons);

    // Getters (Encapsulation)
    const std::string& getUrl() const;
    bool getIsPhishing() const;
    int getSecurityScore() const;
    const std::vector<std::string>& getReasons() const;

    // Setters
    void setUrl(const std::string &u);
    void setIsPhishing(bool phishing);
    void setSecurityScore(int score);
    void setReasons(const std::vector<std::string> &r);
    void addReason(const std::string &reason);

    // Member function to serialize result to valid JSON string
    std::string toJson() const;
};

#endif // SCAN_RESULT_H


