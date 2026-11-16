// PhishingDetector.h
#ifndef PHISHING_DETECTOR_H
#define PHISHING_DETECTOR_H

#include "URLAnalyzer.h"
#include "ScanResult.h"
#include <string>

class PhishingDetector {
private:
    URLAnalyzer analyzer; // composition: uses URLAnalyzer
public:
    explicit PhishingDetector(const std::string& url);
    ScanResult detect() const;
};

#endif // PHISHING_DETECTOR_H

