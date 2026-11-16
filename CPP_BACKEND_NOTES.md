# PRiVY – C++ HTTP API migration

## API layers in this build
- **C++17 HTTP API service** (`src/api_server.cpp`, binary `build/privy_api`): implements `GET /api/health`, `POST /api/detect`, and `POST /api/analyze`; it also owns SQLite-backed scan history retrieval/deletion/clearing and admin aggregate statistics.
- **Node.js/Express application adapter** (`server.js`): still owns website hosting, signup/login, JWT authorization, account management and database initialization. Authenticated scan-history and admin-stat routes validate the JWT/role in Express, then delegate SQLite queries to the C++ service. The `/api/scan` and `/api/analyze` routes call the C++ detector over localhost.
- **Startup** (`start.js`): launches the C++ REST service, waits for its health endpoint, and then launches Express.

Thus URL detection, scan-history data queries/mutations, and admin aggregate statistics are implemented in C++. Node retains authentication/JWT validation and account-management routes, preserving existing site behavior.

## C++ OOP
`URLAnalyzer` encapsulates URL features; `PhishingDetector` computes the risk verdict and score; `ScanResult` serializes the JSON response; `User` and `Admin` demonstrate inheritance/polymorphism.

## Run (macOS/Linux)
1. Install Node dependencies: `npm install`
2. Build C++ programs: `make`
3. Start both services: `npm start`
4. Express website: `http://localhost:3000`
5. C++ API health: `http://127.0.0.1:4001/api/health`
6. C++ detector API: POST JSON to `http://127.0.0.1:4001/api/detect` with body `{"url":"https://example.com"}`
7. C++ scan-history/admin database endpoints are internal routes called by Express: `/api/db/history`, `/api/db/history/delete`, `/api/db/history/clear`, `/api/db/admin/stats`. They use `privy.db` (path passed at startup).

The C++ API binds to loopback only (127.0.0.1), not a public network interface. This is an educational heuristic detector, not a guarantee that any URL is safe.
