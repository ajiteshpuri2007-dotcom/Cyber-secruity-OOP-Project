#!/bin/bash
set -e
cd "$(dirname "$0")"
make
exec ./build/privy_server "${PORT:-3000}" "${DB_PATH:-privy.db}"
