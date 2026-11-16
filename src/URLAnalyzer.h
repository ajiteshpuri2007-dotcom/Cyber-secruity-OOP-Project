#ifndef URL_ANALYZER_H
#define URL_ANALYZER_H

#include <string>
#include <vector>

// C++17 core feature extractor. All URL heuristics live in this class.
class URLAnalyzer {
private:
    std::string url;
    std::string normalizedUrl;
    std::string host;

    void parseHost();
    bool containsIPAddress() const;
    bool containsSuspiciousKeyword() const;
    bool hasExcessiveSubdomains() const;
    bool isShortener() const;
    bool hasUnusualSymbols() const;
    bool usesHttp() const;
    bool containsAtSymbol() const;
    bool hasSuspiciousHyphens() const;
    bool hasSuspiciousTld() const;
    bool hasLongUrl() const;
    bool hasEncodedCharacters() const;
    bool hasMultipleSlashes() const;

public:
    explicit URLAnalyzer(const std::string &url);
    std::vector<std::string> analyze() const;
    const std::string& getURL() const;
    // Feature weights are consumed by the C++ PhishingDetector.
    int getRiskPoints() const;
};

#endif // URL_ANALYZER_H
