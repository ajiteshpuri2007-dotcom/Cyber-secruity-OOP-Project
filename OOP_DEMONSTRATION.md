# OOP Demonstration Additions (PRiVY)

This version keeps the existing UI and adds a formal abstract `Scanner` interface.

## Concepts demonstrated
- **Abstraction:** `Scanner` is abstract because `scan()` is pure virtual.
- **Inheritance:** `PhishingDetector` derives from `Scanner`; `Admin` already derives from `User`.
- **Runtime polymorphism:** `main.cpp --test-oop` stores a `PhishingDetector` in `std::unique_ptr<Scanner>` and invokes `scan()` through the base interface.
- **Function overloading:** `PhishingDetector::detect()` and `PhishingDetector::detect(const std::string&)`.
- **Encapsulation:** private URL feature fields in `URLAnalyzer`, and private fields with getters/setters in `ScanResult`.
- **Composition:** `PhishingDetector` owns/uses a `URLAnalyzer` member.
- **Constructors/destructors:** existing constructors and virtual destructors.

## Verify the OOP demonstration
Build the standalone engine with the project compiler setup and run:

```sh
./build/privy_engine --test-oop
```

The command outputs JSON showing polymorphic user/admin information and a sample scan result.

The UI has not been redesigned. The new abstraction is an internal backend architecture change.
