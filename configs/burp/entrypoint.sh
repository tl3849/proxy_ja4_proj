#!/bin/sh
set -e

mkdir -p /home/burp/.BurpSuite

if [ ! -f /opt/burp/burpsuite.jar ]; then
  echo "Missing /opt/burp/burpsuite.jar. Mount your Burp JAR at ./configs/burp/burpsuite.jar."
  sleep infinity
fi

Xvfb :99 -screen 0 1280x800x24 &
sleep 1
fluxbox >/dev/null 2>&1 &

# VNC + noVNC (web) on :6901
x11vnc -display :99 -nopw -forever -rfbport 5900 -shared >/dev/null 2>&1 &
websockify --web=/usr/share/novnc/ 6901 localhost:5900 >/dev/null 2>&1 &

exec java -jar /opt/burp/burpsuite.jar


