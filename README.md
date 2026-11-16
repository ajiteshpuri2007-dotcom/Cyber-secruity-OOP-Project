# PRiVY — Phishing URL Detection System (C++ Backend)

PRiVY is a phishing URL analysis website. Its user interface is built with HTML, CSS, and browser-side JavaScript. **All server-side functionality is implemented in a native C++17 HTTP server**: API routing, authentication, JWT sessions, password hashing, SQLite queries, scan processing, scan history, admin operations, and static asset serving.

## Architecture

- **Frontend:** HTML, CSS, vanilla JavaScript in `public/` (unchanged user interface)
- **Backend:** C++17 server (`src/api_server.cpp`)
- **Detection:** C++ OOP engine (`URLAnalyzer`, `PhishingDetector`, `ScanResult`)
- **Persistence:** SQLite C API
- **Authentication:** HMAC-SHA256 JWT and bcrypt-compatible `crypt(3)` password hashes on macOS/Linux
- **Node.js / Express:** Not used by the runtime backend. `server.js` and `start.js` have been removed.

## Requirements (macOS / Linux)

- C++ compiler (`g++` or compatible)
- `make`
- SQLite development library
- OpenSSL development library
- macOS/Linux `crypt(3)` with bcrypt support (for password verification and hashing)

On macOS with Homebrew, if required dependencies are missing:

```bash
brew install sqlite openssl
```

## Build and Run

From the project root:

```bash
make clean
make
./build/privy_server 3000 privy.db
```

Or use the helper script:

```bash
./start.sh
```

Then open <http://localhost:3000>. The C++ server serves the frontend and all APIs on the same port. The server binds to `0.0.0.0`; use the local address for a local demonstration.

Optional environment variables (export before starting):

```bash
export JWT_SECRET='replace-with-a-long-random-secret'
export ADMIN_REGISTRATION_KEY='replace-admin-registration-key'
export DEFAULT_ADMIN_PASSWORD='replace-default-admin-password'
export PORT=3000
./start.sh
```

The default seeded administrator is `admin` with password `Admin@12345` when the database has no admin account. Change this before deployment. Existing database contents are kept; the C++ server uses the `privy.db` file passed on startup.

## API Routes

### Authentication and user session

- `POST /api/register` — register a user; admin registration requires the configured admin key
- `POST /api/login` — login using username or email
- `GET /api/me` — authenticated current-user information

### URL analysis and scan history

- `POST /api/analyze` — public URL analysis; optionally records it for an authenticated user
- `POST /api/scan` — authenticated scan and persistence
- `GET /api/history` — authenticated user's scan history
- `DELETE /api/history/:id` — remove one owned scan
- `DELETE /api/history` — clear user's scan history

### Admin (requires admin role)

- `GET /api/admin/stats` — system overview
- `GET /api/admin/users?search=...` — user listing and scan counts
- `POST /api/admin/users` — create a user/admin account
- `PATCH /api/admin/users/:id/role` — update role
- `DELETE /api/admin/users/:id` — delete user and scans
- `GET /api/admin/scans?filter=all|phishing|safe` — scan listing

### Utility

- `GET /api/health` — server health
- `GET /api/oop-info` — C++ OOP architecture information

## Project Structure

```text
.
├── public/                 # Frontend assets
├── src/
│   ├── api_server.cpp      # C++ HTTP server, APIs, auth, SQLite and static hosting
│   ├── URLAnalyzer.cpp/.h  # URL feature analysis
│   ├── PhishingDetector.cpp/.h
│   ├── ScanResult.cpp/.h
│   ├── User.cpp/.h
│   └── Admin.cpp/.h
├── build/                  # Created by make
├── privy.db                # SQLite data store
├── Makefile
└── start.sh
```

## Notes

- The source is designed for macOS/Linux (POSIX sockets and `crypt(3)`).
- Password hashing is compatible with bcrypt-format hashes used by the existing project on platforms whose `crypt(3)` supports bcrypt. Verify that bcrypt support is available on your host before using existing accounts.
- This is a student project. Before public deployment, use a strong secret, change the default admin password, add HTTPS behind a reverse proxy, and review request-size/rate-limiting controls.
