// maximilian.kaul@aisec.fraunhofer.de

// WIP implementation of
// https://github.com/ontio/ontology-crypto/wiki/Anonymous-Credential
// using the relic library https://github.com/relic-toolkit/relic/

#include "platform.h"
#include "pabc_helper.h"
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

static char pabc_dir[PATH_MAX + 1];

static const char *
get_homedir ()
{
  const char *homedir;
  if ((homedir = getenv ("HOME")) == NULL)
  {
    homedir = getpwuid (getuid ())->pw_dir;
  }
  return homedir;
}


static enum GNUNET_GenericReturnValue
write_file (char const *const filename, const char *buffer)
{
  struct GNUNET_DISK_FileHandle *fh;
  fh = GNUNET_DISK_file_open (filename,
                              GNUNET_DISK_OPEN_WRITE
                              | GNUNET_DISK_OPEN_TRUNCATE
                              | GNUNET_DISK_OPEN_CREATE,
                              GNUNET_DISK_PERM_USER_WRITE
                              | GNUNET_DISK_PERM_USER_READ);
  if (fh == NULL)
    return GNUNET_SYSERR;
  if (GNUNET_SYSERR == GNUNET_DISK_file_write (fh,
                                               buffer, strlen (buffer) + 1))
    goto fail;
  GNUNET_DISK_file_close (fh);
  return GNUNET_OK;

fail:
  GNUNET_DISK_file_close (fh);
  return GNUNET_SYSERR;
}


static enum GNUNET_GenericReturnValue
init_pabc_dir ()
{
  size_t filename_size = strlen (get_homedir ()) + 1 + strlen (".local") + 1
                         + strlen ("pabc-reclaim") + 1;
  snprintf (pabc_dir, filename_size, "%s/%s/%s",
            get_homedir (), ".local", "pabc-reclaim");
  return GNUNET_DISK_directory_create (pabc_dir);
}


static const char *
get_pabcdir ()
{
  init_pabc_dir ();
  return pabc_dir;
}


enum GNUNET_GenericReturnValue
read_file (char const *const filename, char **buffer)
{
  struct GNUNET_DISK_FileHandle *fh;
  if (GNUNET_YES != GNUNET_DISK_file_test (filename))
    return GNUNET_SYSERR;

  fh = GNUNET_DISK_file_open (filename,
                              GNUNET_DISK_OPEN_READ,
                              GNUNET_DISK_PERM_USER_READ);
  if (fh == NULL)
    return GNUNET_SYSERR;
  long lSize = GNUNET_DISK_file_seek (fh, 0, GNUNET_DISK_SEEK_END);
  if (lSize < 0)
    goto fail;
  GNUNET_DISK_file_seek (fh, 0, GNUNET_DISK_SEEK_SET);
  *buffer = calloc ((size_t) lSize + 1, sizeof(char));
  if (*buffer == NULL)
    goto fail;

  // copy the file into the buffer:
  size_t r = GNUNET_DISK_file_read (fh, *buffer, (size_t) lSize);
  if (r != (size_t) lSize)
    goto fail;

  GNUNET_DISK_file_close (fh);
  return GNUNET_OK;

fail:
  GNUNET_DISK_file_close (fh);
  GNUNET_free (*buffer);
  return GNUNET_SYSERR;
}


struct pabc_public_parameters *
PABC_read_issuer_ppfile (const char *f, struct pabc_context *const ctx)
{
  if (NULL == ctx)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No global context provided\n");
    return NULL;
  }
  struct pabc_public_parameters *pp;
  char *buffer;
  int r;
  r = read_file (f, &buffer);
  if (GNUNET_OK != r)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Error reading file\n");
    return NULL;
  }
  if (PABC_OK != pabc_decode_and_new_public_parameters (ctx, &pp, buffer))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to decode public parameters\n");
    PABC_FREE_NULL (buffer);
    return NULL;
  }
  PABC_FREE_NULL (buffer);
  return pp;
}


enum GNUNET_GenericReturnValue
PABC_load_public_parameters (struct pabc_context *const ctx,
                             char const *const pp_name,
                             struct pabc_public_parameters **pp)
{
  char fname[PATH_MAX];
  char *pp_filename;
  const char *pdir = get_pabcdir ();

  if (ctx == NULL)
    return GNUNET_SYSERR;
  if (pp_name == NULL)
    return GNUNET_SYSERR;

  GNUNET_STRINGS_urlencode (pp_name, strlen (pp_name), &pp_filename);
  if (GNUNET_YES != GNUNET_DISK_directory_test (pdir, GNUNET_YES))
  {
    GNUNET_free (pp_filename);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Error reading %s\n", pdir);
    return GNUNET_SYSERR;
  }
  snprintf (fname, PATH_MAX, "%s/%s%s", pdir, pp_filename, PABC_PP_EXT);
  if (GNUNET_YES != GNUNET_DISK_file_test (fname))
  {
    GNUNET_free (pp_filename);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Error testing %s\n", fname);
    return GNUNET_SYSERR;
  }
  *pp = PABC_read_issuer_ppfile (fname, ctx);
  if (*pp)
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
}


enum GNUNET_GenericReturnValue
PABC_write_public_parameters (char const *const pp_name,
                              struct pabc_public_parameters *const pp)
{
  char *json;
  char *filename;
  char *pp_filename;
  enum pabc_status status;
  struct pabc_context *ctx = NULL;

  GNUNET_STRINGS_urlencode (pp_name, strlen (pp_name), &pp_filename);
  PABC_ASSERT (pabc_new_ctx (&ctx));
  // store in json file
  status = pabc_encode_public_parameters (ctx, pp, &json);
  if (status != PABC_OK)
  {
    GNUNET_free (pp_filename);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to encode public parameters.\n");
    pabc_free_ctx (&ctx);
    return GNUNET_SYSERR;
  }

  size_t filename_size =
    strlen (get_pabcdir ()) + 1 + strlen (pp_filename) + strlen (PABC_PP_EXT)
    + 1;
  filename = GNUNET_malloc (filename_size);
  if (! filename)
  {
    GNUNET_free (pp_filename);
    PABC_FREE_NULL (json);
    pabc_free_ctx (&ctx);
    return GNUNET_SYSERR;
  }
  snprintf (filename, filename_size, "%s/%s%s", get_pabcdir (), pp_filename,
            PABC_PP_EXT);

  GNUNET_free (pp_filename);
  if (GNUNET_OK != write_file (filename, json))
  {
    PABC_FREE_NULL (filename);
    PABC_FREE_NULL (json);
    pabc_free_ctx (&ctx);
    return GNUNET_SYSERR;
  }
  PABC_FREE_NULL (filename);
  PABC_FREE_NULL (json);
  pabc_free_ctx (&ctx);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
PABC_write_usr_ctx (char const *const usr_name,
                    char const *const pp_name,
                    struct pabc_context const *const ctx,
                    struct pabc_public_parameters const *const pp,
                    struct pabc_user_context *const usr_ctx)
{

  char *pp_filename;
  char *json = NULL;
  enum pabc_status status;
  char *fname = NULL;

  if (NULL == usr_name)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No issuer given.\n");
    return GNUNET_SYSERR;
  }
  if (NULL == pp_name)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No user given.\n");
    return GNUNET_SYSERR;
  }
  if (NULL == ctx)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No context given.\n");
    return GNUNET_SYSERR;
  }
  if (NULL == pp)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No public parameters given.\n");
    return GNUNET_SYSERR;
  }
  if (NULL == usr_ctx)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No user context given.\n");
    return GNUNET_SYSERR;
  }

  GNUNET_STRINGS_urlencode (pp_name, strlen (pp_name), &pp_filename);
  status = pabc_encode_user_ctx (ctx, pp, usr_ctx, &json);
  if (PABC_OK != status)
  {
    GNUNET_free (pp_filename);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to encode user context.\n");
    return status;
  }

  size_t fname_size = strlen (get_pabcdir ()) + 1 + strlen (usr_name) + 1
                      + strlen (pp_filename) + strlen (PABC_USR_EXT) + 1;
  fname = GNUNET_malloc (fname_size);

  snprintf (fname, fname_size, "%s/%s_%s%s", get_pabcdir (), usr_name,
            pp_filename,
            PABC_USR_EXT);

  GNUNET_free (pp_filename);
  if (GNUNET_OK == write_file (fname, json))
  {
    GNUNET_free (fname);
    GNUNET_free (json);
    return GNUNET_OK;
  }
  else
  {
    GNUNET_free (fname);
    GNUNET_free (json);
    return GNUNET_SYSERR;
  }
}


enum GNUNET_GenericReturnValue
PABC_read_usr_ctx (char const *const usr_name,
                   char const *const pp_name,
                   struct pabc_context const *const ctx,
                   struct pabc_public_parameters const *const pp,
                   struct pabc_user_context **usr_ctx)
{
  char *json = NULL;
  char *pp_filename;
  enum pabc_status status;

  char *fname = NULL;

  if (NULL == usr_name)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No issuer given.\n");
    return GNUNET_SYSERR;
  }
  if (NULL == pp_name)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No user given.\n");
    return GNUNET_SYSERR;
  }
  if (NULL == ctx)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No context given.\n");
    return GNUNET_SYSERR;
  }
  if (NULL == pp)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No public parameters given.\n");
    return GNUNET_SYSERR;
  }
  if (NULL == usr_ctx)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No user context given.\n");
    return GNUNET_SYSERR;
  }
  GNUNET_STRINGS_urlencode (pp_name, strlen (pp_name), &pp_filename);

  size_t fname_size = strlen (get_pabcdir ()) + 1 + strlen (usr_name) + 1
                      + strlen (pp_filename) + strlen (PABC_USR_EXT) + 1;
  fname = GNUNET_malloc (fname_size);
  snprintf (fname, fname_size, "%s/%s_%s%s", get_pabcdir (), usr_name,
            pp_filename,
            PABC_USR_EXT);
  GNUNET_free (pp_filename);
  if (GNUNET_OK != read_file (fname, &json))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to read `%s'\n", fname);
    PABC_FREE_NULL (fname);
    return GNUNET_SYSERR;
  }
  GNUNET_free (fname);

  status = pabc_new_user_context (ctx, pp, usr_ctx);
  if (PABC_OK != status)
  {
    GNUNET_free (json);
    return GNUNET_SYSERR;
  }
  status = pabc_decode_user_ctx (ctx, pp, *usr_ctx, json);
  GNUNET_free (json);
  if (PABC_OK != status)
  {
    pabc_free_user_context (ctx, pp, usr_ctx);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to encode user context.\n");
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}
