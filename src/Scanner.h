#ifndef SCANNER_H
#define SCANNER_H

#include "ScanResult.h"

// Abstract base class: every concrete security scanner must implement scan().
class Scanner {
public:
    virtual ~Scanner() = default;
    virtual ScanResult scan() const = 0;
};

#endif // SCANNER_H
