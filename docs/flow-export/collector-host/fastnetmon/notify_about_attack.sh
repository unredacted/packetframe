#!/bin/sh
# FastNetMon's action hook: one line per ban or unban in log/actions.log.
# Replace it to act (Phase 2 mitigation is PacketFrame's, not this).
echo "$(date -u +%FT%TZ) ip=$1 direction=$2 pps=$3 action=$4" >> /var/log/fnm/actions.log
cat > /dev/null
