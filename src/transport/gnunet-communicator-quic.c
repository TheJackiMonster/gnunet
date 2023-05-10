#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"

int 
main(int argc, char *const *argv) 
{
    static const struct GNUNET_GETOPT_CommandLineOption options[] = {
        GNUNET_GETOPT_OPTION_END
    };
    
    int ret;
    ret =  (GNUNET_OK == GNUNET_PROGRAM_run(argc, 
                              argv, 
                              "gnunet-communicator-quic", 
                              "quic",
                              options,
                              NULL,
                              NULL))
            ? 0 
            : 1;

    return ret;
}
