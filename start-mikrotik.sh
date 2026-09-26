#!/usr/bin/env bash
set -euo pipefail

dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$dir"

# Map origin: args 1-2, else NETWORKER_ORIGIN_LAT / NETWORKER_ORIGIN_LON, else London.
lat="${1:-${NETWORKER_ORIGIN_LAT:-51.5074}}"
lon="${2:-${NETWORKER_ORIGIN_LON:--0.1278}}"

pnpm --dir frontend run build
go build -o networker ./cmd/networker
# .env holds the RouterOS REST user (CERT_NAME) and password (CERT_PASS). The
# password goes over stdin, so it is never in argv or the environment.
. "$dir/.env"
printf '%s' "$CERT_PASS" | sudo -- "$dir/networker" \
  -city-db "$dir/geoip/GeoLite2-City.mmdb" \
  -origin-lat "$lat" \
  -origin-lon "$lon" \
  -router-url https://192.168.0.1 \
  -router-user "$CERT_NAME" \
  -router-password-file /dev/stdin \
  -router-ca "$HOME/.config/networker/mikrotik-local-ca.crt"
