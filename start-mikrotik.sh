#!/usr/bin/env bash
set -euo pipefail

dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$dir"

# Map origin: args 1-2, else NETWORKER_ORIGIN_LAT / NETWORKER_ORIGIN_LON, else London.
lat="${1:-${NETWORKER_ORIGIN_LAT:-51.5074}}"
lon="${2:-${NETWORKER_ORIGIN_LON:--0.1278}}"
state="${XDG_STATE_HOME:-$HOME/.local/state}/networker"

pnpm --dir frontend run build
go build -o networker ./cmd/networker
# .env holds the RouterOS REST user (CERT_NAME) and password (CERT_PASS). The
# password goes over stdin, so it is never in argv or the environment.
. "$dir/.env"
printf '%s' "$CERT_PASS" | sudo env \
  NETWORKER_CITY_DB="$dir/geoip/GeoLite2-City.mmdb" \
  NETWORKER_HISTORY_DB="$state/history.db" \
  NETWORKER_SNITCH_DB="$state/snitch.db" \
  NETWORKER_ORIGIN_LAT="$lat" \
  NETWORKER_ORIGIN_LON="$lon" \
  NETWORKER_ROUTER_URL=https://192.168.0.1 \
  NETWORKER_ROUTER_USER="$CERT_NAME" \
  NETWORKER_ROUTER_PASSWORD_FILE=/dev/stdin \
  NETWORKER_ROUTER_CA="$HOME/.config/networker/mikrotik-local-ca.crt" \
  "$dir/networker"
