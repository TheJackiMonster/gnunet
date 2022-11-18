# FROM ubuntu:20.04
FROM debian:stable

ENV DEBIAN_FRONTEND noninteractive

# Install tools and dependencies
RUN apt-get update && \
      apt-get upgrade && \
      apt-get -y install --no-install-recommends \
      apt-utils

# Install tools and dependencies
RUN apt-get update && \
      apt-get upgrade && \
      apt-get -y install --no-install-recommends \
      ca-certificates \
      iptables \
      python3 \
      python3-pip \
      iproute2 \
      net-tools \
      libsasl2-modules \
      git \
      automake \
      autopoint \
      autoconf \
      recutils \
      make \
      libssl-dev \
      ninja-build \
      meson \
      curl \
      libcurl4-gnutls-dev \
      libsodium-dev \
      libsodium23 \
      libjansson-dev \
      texinfo \
      libtool \
      libltdl-dev \
      libgpg-error-dev \
      libidn11-dev \
      libunistring-dev \
      libglpk-dev \
      libbluetooth-dev \
      libextractor-dev \
      libmicrohttpd-dev \
      libgnutls28-dev \
      libgcrypt20-dev \
      libpq-dev \
      libsqlite3-dev \
      wget
RUN apt-get clean all && \
    apt-get -y autoremove && \
    rm -rf \
      /var/lib/apt/lists/* \
      /tmp/*

# Install jose
RUN wget -O /tmp/jose.tar.gz https://github.com/latchset/jose/archive/refs/tags/v11.tar.gz
RUN cd /tmp && \
      tar xvf jose.tar.gz && \
      cd jose-11 && \
      mkdir build && \
      cd build && \
      meson .. --prefix=/usr/local/lib && \
      ninja && \
      ninja install && \
      cd / && \
      rm -rf /tmp/jose-11/*

# Intall Python Packages for Documentation
RUN pip3 install \
    docutils==0.17.1 \
    sphinx \
    sphinx-rtd-theme

COPY . /tmp/gnunet

# ENV VERSION=0.18.1
# ENV HASH=719fc54734ee54c36ff619a6aa2d659655db012c40f9210c0859459c435fce1a
# RUN wget "ftpmirror.gnu.org/gnunet/gnunet-$VERSION.tar.gz" -P /tmp

# Check the gnunet download integrity
# RUN echo "$HASH /tmp/gnunet-$VERSION.tar.gz" | sha256sum --check --status

# Extract gnunet
# RUN mkdir /tmp/gnunet && tar xf "/tmp/gnunet-$VERSION.tar.gz" -C /tmp/gnunet --strip-components=1

# Install gnunet
# ENV GNUNET_PREFIX=/usr/local/lib
# ENV CFLAGS '-g -Wall -O0'
# 
# RUN cd /tmp/gnunet && \
#       ./configure \
#         --prefix="$GNUNET_PREFIX/.." \
#         --enable-logging=verbose && \
#       make -j && \
#       make install && \
#       ldconfig

RUN cd /tmp/gnunet && \
      ./bootstrap && \
      ./configure \
        --prefix="$GNUNET_PREFIX/.." \
        --enable-logging=verbose && \
      make -j && \
      make install && \
      ldconfig

# Configure GNUnet
RUN cp /tmp/gnunet/contrib/docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint
RUN chmod 755 /usr/local/bin/docker-entrypoint

ENV LOCAL_PORT_RANGE='40001 40200'
ENV PATH "$GNUNET_PREFIX/bin:/usr/local/bin:$PATH"

ENTRYPOINT ["docker-entrypoint"]
