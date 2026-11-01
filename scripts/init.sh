#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
if [ "${EUID}" -ne 0 ]; then printf 'Run as root to prepare UID 65532 volumes.\n' >&2; exit 1; fi
origin=${1:-}
if [[ ! "$origin" =~ ^https://[a-zA-Z0-9.-]+(:[0-9]+)?$ ]]; then printf 'Usage: sudo bash scripts/init.sh https://monitor.example.com\n' >&2; exit 1; fi
mkdir -p secrets data
chown 65532:65532 data
chmod 700 data
if [ ! -e .env ]; then
 prefix=$(openssl rand -hex 18)
 printf 'URL_PREFIX=/%s\nPUBLIC_ORIGIN=%s\nTRUSTED_PROXY=\n' "$prefix" "$origin" > .env
fi
if [ ! -e secrets/agent.crt ] && [ ! -e secrets/agent.key ]; then
 openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' -keyout secrets/agent.key -out secrets/agent.crt 2>/dev/null
fi
test -s secrets/agent.key && test -s secrets/agent.crt
chown root:65532 secrets secrets/agent.key secrets/agent.crt
chmod 750 secrets
chmod 640 secrets/agent.key secrets/agent.crt
docker compose build web
IFS= read -r -s -p 'Administrator password (14–256 Unicode characters): ' tz_admin_password
printf '\n'
printf '%s' "$tz_admin_password" | docker compose run --rm -T --no-deps web init-admin
unset tz_admin_password
docker compose up -d --no-deps web
printf 'Initialized. Configure a trusted HTTPS reverse proxy; see docs/HTTPS.md.\n'
