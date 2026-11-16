// ScanResult.cpp
#include "ScanResult.h"
#include <sstream>

std::string ScanResult::escapeJson(const std::string &input) {
    std::ostringstream ss;
    for (char c : input) {
        switch (c) {
            case '"': ss << "\\\""; break;
            case '\\': ss << "\\\\"; break;
            case '\b': ss << "\\b"; break;
            case '\f': ss << "\\f"; break;
            case '\n': ss << "\\n"; break;
            case '\r': ss << "\\r"; break;
            case '\t': ss << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    // Control character
                    ss << "\\u00" << ((c >> 4) & 0xF) << (c & 0xF);
                } else {
                    ss << c;
                }
                break;
        }
    }
    return ss.str();
}

ScanResult::ScanResult()
    : url(""), isPhishing(false), securityScore(100), reasons() {}

ScanResult::ScanResult(const std::string &url, bool isPhishing, int securityScore, const std::vector<std::string> &reasons)
    : url(url), isPhishing(isPhishing), securityScore(securityScore), reasons(reasons) {}

const std::string& ScanResult::getUrl() const {
    return url;
}

bool ScanResult::getIsPhishing() const {
    return isPhishing;
}

int ScanResult::getSecurityScore() const {
    return securityScore;
}

const std::vector<std::string>& ScanResult::getReasons() const {
    return reasons;
}

void ScanResult::setUrl(const std::string &u) {
    url = u;
}

void ScanResult::setIsPhishing(bool phishing) {
    isPhishing = phishing;
}

void ScanResult::setSecurityScore(int score) {
    securityScore = score;
}

void ScanResult::setReasons(const std::vector<std::string> &r) {
    reasons = r;
}

void ScanResult::addReason(const std::string &reason) {
    reasons.push_back(reason);
}

std::string ScanResult::toJson() const {
    std::ostringstream ss;
    ss << "{\"url\":\"" << escapeJson(url) << "\",";
    ss << "\"isPhishing\":" << (isPhishing ? "true" : "false") << ",";
    ss << "\"securityScore\":" << securityScore << ",";
    ss << "\"reasons\":[";
    for (size_t i = 0; i < reasons.size(); ++i) {
        ss << "\"" << escapeJson(reasons[i]) << "\"";
        if (i + 1 < reasons.size()) {
            ss << ",";
        }
    }
    ss << "]}";
    return ss.str();
}


