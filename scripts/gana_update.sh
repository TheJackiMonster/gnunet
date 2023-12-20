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
      cwd=$PWD
      cd contrib/gana || exit 1
      # GNS
      echo "Updating GNS record types"
      cd gnu-name-system-record-types && \
         make >/dev/null && \
         cp gnu_name_system_record_types.h ../../../src/include/ || exit 1
      echo "Creating default TLDs"
      cd ../gnu-name-system-default-tlds && \
         make >/dev/null && \
         cp tlds.conf ../../../src/service/gns || exit 1
      echo "Creating default GNS protocol numbers"
      cd ../gns-protocol-numbers && \
         make >/dev/null && \
         cp gnu_name_system_protocols.h ../../../src/include/ || exit 1
      echo "Creating default GNS service port nummbers"
      cd ../gns-service-port-numbers && \
         make >/dev/null && \
         cp gnu_name_system_service_ports.h ../../../src/include/ || exit 1

      # Signatures
      echo "Updating GNUnet signatures"
      cd ../gnunet-signatures && \
         make >/dev/null && \
         cp gnunet_signatures.h ../../../src/include || exit 1
      # DHT Block Types
      echo "Updating DHT record types"
      cd ../gnunet-dht-block-types && \
         make >/dev/null && \
         cp gnunet_dht_block_types.h ../../../src/include || exit 1
      echo "Generating GNUnet error types"
      cd ../gnunet-error-codes && \
         make >/dev/null && \
         cp gnunet_error_codes.h ../../../src/include && \
         cp gnunet_error_codes.c ../../../src/lib/util || exit 1
      cd $cwd
    else
      echo "ERROR: No recutils found! Unable to generate recent GANA headers and configs."
      exit 1
    fi
    echo "GANA finished"
}

gana_update
