#include "URLAnalyzer.h"
#include <algorithm>
#include <cctype>
#include <regex>
#include <sstream>

namespace {
std::string lowerCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}
}

URLAnalyzer::URLAnalyzer(const std::string &input) : url(input), normalizedUrl(lowerCopy(input)) {
    parseHost();
}

const std::string& URLAnalyzer::getURL() const { return url; }

void URLAnalyzer::parseHost() {
    std::string rest = normalizedUrl;
    const auto scheme = rest.find("://");
    if (scheme != std::string::npos) rest = rest.substr(scheme + 3);
    // Remove userinfo before host (userinfo is itself separately flagged).
    const auto at = rest.rfind('@');
    if (at != std::string::npos) rest = rest.substr(at + 1);
    const auto end = rest.find_first_of("/?#");
    if (end != std::string::npos) rest = rest.substr(0, end);
    // Remove port, but preserve IPv6 bracket notation.
    if (!rest.empty() && rest.front() == '[') {
        const auto close = rest.find(']');
        if (close != std::string::npos) rest = rest.substr(0, close + 1);
    } else {
        const auto colon = rest.rfind(':');
        if (colon != std::string::npos) rest = rest.substr(0, colon);
    }
    host = rest;
}

bool URLAnalyzer::containsIPAddress() const {
    // Strict IPv4 octet bounds; IPv6 literal hosts are also flagged.
    if (host.find(':') != std::string::npos && host.size() > 2) return true;
    static const std::regex ipv4(R"(^([0-9]{1,3}\.){3}[0-9]{1,3}$)");
    if (!std::regex_match(host, ipv4)) return false;
    std::stringstream ss(host); std::string part;
    while (std::getline(ss, part, '.')) {
        try { if (std::stoi(part) > 255) return false; }
        catch (...) { return false; }
    }
    return true;
}

bool URLAnalyzer::containsSuspiciousKeyword() const {
    static const std::vector<std::string> words = {
        "login", "signin", "bank", "verify", "account", "update", "secure", "password",
        "credential", "wallet", "authenticate", "billing", "confirm-identity", "recover",
        "reset", "payment", "webscr", "unlock"
    };
    for (const auto &word : words) if (normalizedUrl.find(word) != std::string::npos) return true;
    return false;
}

bool URLAnalyzer::hasExcessiveSubdomains() const {
    return std::count(host.begin(), host.end(), '.') > 3;
}

bool URLAnalyzer::isShortener() const {
    static const std::vector<std::string> hosts = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd",
        "cutt.ly", "rb.gy", "shorturl.at", "lnkd.in"
    };
    return std::find(hosts.begin(), hosts.end(), host) != hosts.end();
}

bool URLAnalyzer::hasUnusualSymbols() const {
    static const std::regex symbols(R"([{}\[\]<>"\\])");
    return std::regex_search(url, symbols);
}

bool URLAnalyzer::usesHttp() const { return normalizedUrl.rfind("http://", 0) == 0; }
bool URLAnalyzer::containsAtSymbol() const { return url.find('@') != std::string::npos; }
bool URLAnalyzer::hasSuspiciousHyphens() const { return std::count(host.begin(), host.end(), '-') >= 3; }

bool URLAnalyzer::hasSuspiciousTld() const {
    static const std::vector<std::string> tlds = {
        ".zip", ".mov", ".click", ".work", ".country", ".stream", ".gq", ".tk", ".ml", ".cf"
    };
    for (const auto &tld : tlds) {
        if (host.size() >= tld.size() && host.compare(host.size() - tld.size(), tld.size(), tld) == 0) return true;
    }
    return false;
}

bool URLAnalyzer::hasLongUrl() const { return url.size() > 120; }

bool URLAnalyzer::hasEncodedCharacters() const {
    return normalizedUrl.find("%") != std::string::npos;
}

bool URLAnalyzer::hasMultipleSlashes() const {
    const auto scheme = normalizedUrl.find("://");
    const auto pathStart = scheme == std::string::npos ? 0 : scheme + 3;
    const auto slash = normalizedUrl.find("//", pathStart);
    return slash != std::string::npos;
}

std::vector<std::string> URLAnalyzer::analyze() const {
    std::vector<std::string> reasons;
    if (containsIPAddress()) reasons.emplace_back("Uses IP address instead of domain");
    if (containsSuspiciousKeyword()) reasons.emplace_back("Contains suspicious keyword");
    if (hasExcessiveSubdomains()) reasons.emplace_back("Excessive subdomains");
    if (isShortener()) reasons.emplace_back("Uses known URL shortener");
    if (hasUnusualSymbols()) reasons.emplace_back("Contains unusual symbols");
    if (usesHttp()) reasons.emplace_back("Uses HTTP instead of HTTPS");
    if (containsAtSymbol()) reasons.emplace_back("Contains '@' symbol (userinfo redirect / domain obfuscation)");
    if (hasSuspiciousHyphens()) reasons.emplace_back("Multiple hyphens in domain name (brand spoofing pattern)");
    if (hasSuspiciousTld()) reasons.emplace_back("Uses a TLD commonly abused in suspicious URLs");
    if (hasLongUrl()) reasons.emplace_back("Unusually long URL");
    if (hasEncodedCharacters()) reasons.emplace_back("Contains URL-encoded characters");
    if (hasMultipleSlashes()) reasons.emplace_back("Contains repeated slashes in URL path");
    return reasons;
}

int URLAnalyzer::getRiskPoints() const {
    int points = 0;
    if (containsIPAddress()) points += 30;
    if (containsSuspiciousKeyword()) points += 10;
    if (hasExcessiveSubdomains()) points += 15;
    if (isShortener()) points += 20;
    if (hasUnusualSymbols()) points += 15;
    if (usesHttp()) points += 10;
    if (containsAtSymbol()) points += 25;
    if (hasSuspiciousHyphens()) points += 15;
    if (hasSuspiciousTld()) points += 20;
    if (hasLongUrl()) points += 10;
    if (hasEncodedCharacters()) points += 5;
    if (hasMultipleSlashes()) points += 5;
    return points;
}
