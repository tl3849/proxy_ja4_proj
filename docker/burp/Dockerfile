FROM debian:stable-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    default-jre-headless xvfb x11vnc fluxbox novnc websockify net-tools ca-certificates tcpdump \
  && rm -rf /var/lib/apt/lists/*

RUN useradd -ms /bin/bash burp
USER burp
WORKDIR /home/burp

ENV DISPLAY=:99
EXPOSE 8080 6901

CMD ["/bin/sh", "/home/burp/entrypoint.sh"]


