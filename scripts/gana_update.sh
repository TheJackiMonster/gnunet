# This is more portable than `which' but comes with
# the caveat of not(?) properly working on busybox's ash:
existence()
{
    type "$1" >/dev/null 2>&1
}

gana_update()
{
    if [ ! -z $GNUNET_SKIP_GANA ]; then
      echo "Skipping GANA update"
      return
    fi
    echo "Updating GANA..."
    if existence recfmt; then
      GNUNET_SRC_ROOT=$PWD
      cd contrib/gana || exit 1
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
      cd $GNUNET_SRC_ROOT
    else
      echo "ERROR: No recutils found! Unable to generate recent GANA headers and configs."
      exit 1
    fi
    echo "GANA finished"
}

gana_update
