#!/bin/sh
# Writes fastnetmon.conf from the pinned image's own stock file, with what
# PacketFrame's sFlow needs, and networks_list from your prefixes.
#
#   ./setup.sh 203.0.113.0/24 2001:db8::/32
#
# Thresholds stay at FastNetMon's defaults: set them for your traffic in
# fastnetmon.conf before relying on a ban.
set -eu
cd "$(dirname "$0")"
[ $# -gt 0 ] || { echo "usage: $0 <prefix you protect>..." >&2; exit 2; }
img=$(awk '$1 == "image:" { print $2 }' compose.yml)
docker run --rm --network none --entrypoint cat "$img" /etc/fastnetmon.conf > fastnetmon.conf.orig
cp fastnetmon.conf.orig fastnetmon.conf
set_key() {
  grep -qE "^$1 *=" fastnetmon.conf || { echo "no \`$1\` in $img's config" >&2; exit 1; }
  sed -i.bak -E "s|^$1 *=.*|$1 = $2|" fastnetmon.conf
}
set_key sflow on
set_key netflow off
# PacketFrame's coverage reasons over 5 s windows; so does this.
set_key average_calculation_time 5
# Inside the container; compose publishes it on the host's loopback only.
set_key prometheus_host 0.0.0.0
rm -f fastnetmon.conf.bak
printf '%s\n' "$@" > networks_list
mkdir -p log
diff fastnetmon.conf.orig fastnetmon.conf || true
