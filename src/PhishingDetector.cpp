#include "PhishingDetector.h"
#include <algorithm>

PhishingDetector::PhishingDetector(const std::string& url)
    : analyzer(url) {}

ScanResult PhishingDetector::detect() const {
    const auto reasons = analyzer.analyze();
    const int riskPoints = analyzer.getRiskPoints();
    const int score = std::max(0, 100 - riskPoints);
    // Conservative heuristic threshold: several combined signals are required.
    const bool isPhishing = riskPoints >= 30;
    return ScanResult(analyzer.getURL(), isPhishing, score, reasons);
}
