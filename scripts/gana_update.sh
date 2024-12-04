# This is more portable than `which' but comes with
# the caveat of not(?) properly working on busybox's ash:
GNUNET_SRC_ROOT=$PWD
if [ ! -f $GNUNET_SRC_ROOT/scripts/gana_update.sh ]; then
  echo "Please run this script from the root of the gnunet source tree!"
  exit 1
fi

COMMITISH=""
if [ ! -z $1 ]; then
  COMMITISH=$1
fi

cleanup() {
    if [ -d $GANA_TMP ]; then
      rm -rf $GANA_TMP
    fi
    cd $GNUNET_SRC_ROOT
}

# This is more portable than `which' but comes with
# the caveat of not(?) properly working on busybox's ash:
existence()
{
    type "$1" >/dev/null 2>&1
}

gana_update()
{
    echo "Updating GANA..."
    if ! existence git; then
      echo "Script requires git"
      exit 1
    fi
    if ! existence recfmt; then
      echo "Script requires recutils"
      exit 1
    fi
    GANA_TMP=`mktemp -d`
    cd $GANA_TMP || exit 1
    git clone git://git.gnunet.org/gana.git
    cd gana || exit 1
    if [ ! -z $COMMITISH ]; then
      git checkout $COMMITISH || exit 1
    fi
    # GNS
    echo "Updating GNS record types"
    make -C gnu-name-system-record-types >/dev/null && \
       cp gnu-name-system-record-types/gnu_name_system_record_types.h $GNUNET_SRC_ROOT/src/include/ || exit 1
    echo "Creating default TLDs"
    make -C gnu-name-system-default-tlds >/dev/null && \
       cp gnu-name-system-default-tlds/tlds.conf $GNUNET_SRC_ROOT/src/service/gns || exit 1
    echo "Creating default GNS protocol numbers"
    make -C gns-protocol-numbers >/dev/null && \
       cp gns-protocol-numbers/gnu_name_system_protocols.h $GNUNET_SRC_ROOT/src/include/ || exit 1
    echo "Creating default GNS service port numbers"
    make -C gns-service-port-numbers >/dev/null && \
       cp gns-service-port-numbers/gnu_name_system_service_ports.h $GNUNET_SRC_ROOT/src/include/ || exit 1

    # Signatures
    echo "Updating GNUnet signatures"
    make -C gnunet-signatures >/dev/null && \
       cp gnunet-signatures/gnunet_signatures.h $GNUNET_SRC_ROOT/src/include || exit 1
    # DHT Block Types
    echo "Updating DHT record types"
    make -C gnunet-dht-block-types >/dev/null && \
       cp gnunet-dht-block-types/gnunet_dht_block_types.h $GNUNET_SRC_ROOT/src/include || exit 1
    echo "Generating GNUnet error types"
    make -C gnunet-error-codes >/dev/null && \
       cp gnunet-error-codes/gnunet_error_codes.h $GNUNET_SRC_ROOT/src/include && \
       cp gnunet-error-codes/gnunet_error_codes.c $GNUNET_SRC_ROOT/src/lib/util || exit 1
    echo "GANA finished"
}

trap cleanup EXIT
gana_update
