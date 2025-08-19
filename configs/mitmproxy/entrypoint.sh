#!/usr/bin/env sh
set -e
# install tcpdump depending on base image
if command -v apk >/dev/null 2>&1; then
  apk add --no-cache tcpdump
elif command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y tcpdump procps net-tools
fi
exec mitmdump --mode regular --listen-host 0.0.0.0 --listen-port 8080 --set confdir=/home/mitmproxy/.mitmproxy