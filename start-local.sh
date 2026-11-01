#!/usr/bin/env bash
set -euo pipefail

# Map origin: args 1-2, else NETWORKER_ORIGIN_LAT / NETWORKER_ORIGIN_LON, else London.
lat="${1:-${NETWORKER_ORIGIN_LAT:-51.5074}}"
lon="${2:-${NETWORKER_ORIGIN_LON:--0.1278}}"
state="${XDG_STATE_HOME:-$HOME/.local/state}/networker"

pnpm --dir frontend run build
go build -o networker ./cmd/networker
# sudo drops the environment, so everything is passed through env. Any other
# NETWORKER_* setting goes on this line too; see README "Configuration".
sudo env \
  NETWORKER_CITY_DB=./geoip/GeoLite2-City.mmdb \
  NETWORKER_HISTORY_DB="$state/history.db" \
  NETWORKER_SNITCH_DB="$state/snitch.db" \
  NETWORKER_ORIGIN_LAT="$lat" \
  NETWORKER_ORIGIN_LON="$lon" \
  ./networker
