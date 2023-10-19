#include "platform.h"
#include "gnunet_util_lib.h"
#include <pabc/pabc.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define PABC_ISK_EXT ".isk"

#define PABC_PP_EXT ".pp"

#define PABC_USR_EXT ".usr"

#define PABC_ATTR_DELIM "="

enum GNUNET_GenericReturnValue
PABC_write_public_parameters (char const *const pp_name,
                              struct pabc_public_parameters *const pp);


enum GNUNET_GenericReturnValue
PABC_load_public_parameters (struct pabc_context *const ctx,
                             char const *const pp_name,
                             struct pabc_public_parameters **pp);

enum GNUNET_GenericReturnValue
PABC_write_usr_ctx (char const *const user_name,
                    char const *const pp_name,
                    struct pabc_context const *const ctx,
                    struct pabc_public_parameters const *const
                    pp,
                    struct pabc_user_context *const usr_ctx);

enum GNUNET_GenericReturnValue
PABC_read_usr_ctx (char const *const user_name,
                   char const *const pp_name,
                   struct pabc_context const *const ctx,
                   struct pabc_public_parameters const *const
                   pp,
                   struct pabc_user_context **usr_ctx);
