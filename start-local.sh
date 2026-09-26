#!/usr/bin/env bash
set -euo pipefail

# Map origin: args 1-2, else NETWORKER_ORIGIN_LAT / NETWORKER_ORIGIN_LON, else London.
lat="${1:-${NETWORKER_ORIGIN_LAT:-51.5074}}"
lon="${2:-${NETWORKER_ORIGIN_LON:--0.1278}}"

pnpm --dir frontend run build
go build -o networker ./cmd/networker
sudo ./networker \
  -city-db ./geoip/GeoLite2-City.mmdb \
  -origin-lat "$lat" \
  -origin-lon "$lon"
