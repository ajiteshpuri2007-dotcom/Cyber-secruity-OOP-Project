// PhishingDetector.h
#ifndef PHISHING_DETECTOR_H
#define PHISHING_DETECTOR_H

#include "URLAnalyzer.h"
#include "ScanResult.h"
#include "Scanner.h"
#include <string>

class PhishingDetector : public Scanner {
private:
    URLAnalyzer analyzer; // composition: uses URLAnalyzer
public:
    explicit PhishingDetector(const std::string& url);
    ScanResult detect() const;
    ScanResult scan() const override;
    ScanResult detect(const std::string& url) const; // function overloading
};

#endif // PHISHING_DETECTOR_H

