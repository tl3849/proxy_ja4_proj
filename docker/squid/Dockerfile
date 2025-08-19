FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV SQUID_VERSION=6.10

# Install dependencies in a single layer to reduce image size
RUN apt-get update && \
    apt-get install -y build-essential \
    libssl-dev \
    pkg-config \
    wget \
    ca-certificates \
    libxml2-dev \
    libcppunit-dev \
    libexpat1-dev \
    libldap2-dev \
    libpam0g-dev \
    libdb-dev \
    libnetfilter-conntrack-dev \
    libnetfilter-conntrack3 \
    libcap2-dev \
    perl \
    # Runtime dependencies
    libssl3 \
    libxml2 \
    libcppunit-1.15-0 \
    libexpat1 \
    libldap-2.5-0 \
    libpam0g \
    libdb5.3 \
    libnetfilter-conntrack3 \
    libcap2 \
    # Add helpers for debugging
    iproute2 \
    net-tools \
    vim \
    curl \
    strace \
    # Add netcat for health checks
    netcat \
    # Add additional SSL-related packages
    openssl \
    libssl-dev \
    && mkdir -p /build

WORKDIR /build

# Download and build Squid with proper error checking
RUN wget http://www.squid-cache.org/Versions/v6/squid-${SQUID_VERSION}.tar.xz && \
    tar -xf squid-${SQUID_VERSION}.tar.xz && \
    cd squid-${SQUID_VERSION} && \
    ./configure --prefix=/usr --localstatedir=/var --libexecdir=/usr/lib/squid \
    --datadir=/usr/share/squid --sysconfdir=/etc/squid --with-default-user=proxy \
    --with-openssl --enable-ssl-crtd --enable-ssl \
    && make -j$(nproc) && make install


# Set up directories and permissions - don't create ssl_db here as it will be tmpfs mounted
RUN mkdir -p /var/log/squid /var/cache/squid /etc/squid && \
    chown -R proxy:proxy /var/log/squid /var/cache/squid /etc/squid && \
    chmod 640 /etc/squid/squid.conf || true && \
    # Initialize cache directories
    /usr/sbin/squid -z
