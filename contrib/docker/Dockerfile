FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive

# Install tools and dependencies
RUN apt-get update
RUN apt-get upgrade
RUN apt-get -y install --no-install-recommends \
      ca-certificates \
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
      meson .. --prefix=/usr && \
      ninja && \
      ninja install && \
      cd / && \
      rm -rf /tmp/jose-11/*

# Install GNUnet
ENV GNUNET_PREFIX=/usr/local/lib
ENV CFLAGS '-g -Wall -O0'

COPY . /gnunet
WORKDIR /gnunet
RUN ./bootstrap --no-doc
RUN ./configure \
	--with-nssdir=/lib \
	--prefix="$GNUNET_PREFIX/.." \
	--enable-logging=verbose
RUN make -j
RUN make install 
RUN ldconfig
WORKDIR /
RUN rm -rf /gnunet

# RUN cd /gnunet && \
#       ./bootstrap && \
#       ./configure \
#         --with-nssdir=/lib \
#         --prefix="$GNUNET_PREFIX" \
#         --enable-logging=verbose && \
#       make -j && \
#       make install && \
#       ldconfig && \
#     cd - && \
#     rm -fr /gnunet

# Configure GNUnet
COPY ./contrib/docker/gnunet.conf /etc/gnunet.conf
COPY ./contrib/docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint
RUN chmod 755 /usr/local/bin/docker-entrypoint

ENV LOCAL_PORT_RANGE='40001 40200'
ENV PATH "$GNUNET_PREFIX/bin:/usr/local/bin:$PATH"

ENTRYPOINT ["docker-entrypoint"]
