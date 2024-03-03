/*
     This file is part of GNUnet.
     Copyright (C) 2022 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file hello/test_hello-uri.c
 * @brief test for helper library for handling URI-based HELLOs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_signatures.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_uri_lib.h"


/**
 * Check for expected URIs.
 *
 * @param cls a `unsigned int*`, bitmask set to found URIs
 * @param uri URI to check for
 */
static void
check_uris (void *cls,
            const struct GNUNET_PeerIdentity *pid,
            const char *uri)
{
  unsigned int *found = cls;

  if (0 == strcmp (uri,
                   "test://address"))
    *found |= 1;
  else if (0 == strcmp (uri,
                        "test://more"))
    *found |= 2;
  else
    *found = (unsigned int) -1;
}


int
main (int argc,
      char *argv[])
{
  struct GNUNET_PeerIdentity pid;
  struct GNUNET_HELLO_Builder *b;
  struct GNUNET_CRYPTO_EddsaPrivateKey priv;

  GNUNET_log_setup ("test-hell-uri",
                    "WARNING",
                    NULL);
  GNUNET_CRYPTO_eddsa_key_create (&priv);
  GNUNET_CRYPTO_eddsa_key_get_public (&priv,
                                      &pid.public_key);
  b = GNUNET_HELLO_builder_new (&pid);
  GNUNET_assert (GNUNET_SYSERR ==
                 GNUNET_HELLO_builder_add_address (b,
                                                   "invalid"));
  GNUNET_assert (GNUNET_SYSERR ==
                 GNUNET_HELLO_builder_add_address (b,
                                                   "i%v://bla"));
  GNUNET_assert (GNUNET_SYSERR ==
                 GNUNET_HELLO_builder_add_address (b,
                                                   "://empty"));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_builder_add_address (b,
                                                   "test://address"));
  GNUNET_assert (GNUNET_NO ==
                 GNUNET_HELLO_builder_add_address (b,
                                                   "test://address"));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_builder_add_address (b,
                                                   "test://more"));
  {
    void *block;
    size_t block_size = 0;
    struct GNUNET_HELLO_Builder *b2;
    const struct GNUNET_PeerIdentity *p2;
    unsigned int found;

    GNUNET_assert (GNUNET_NO ==
                   GNUNET_HELLO_builder_to_block (b,
                                                  &priv,
                                                  NULL,
                                                  &block_size,
                                                  GNUNET_TIME_UNIT_FOREVER_REL));
    GNUNET_assert (GNUNET_NO ==
                   GNUNET_HELLO_builder_to_block (b,
                                                  &priv,
                                                  NULL,
                                                  &block_size,
                                                  GNUNET_TIME_UNIT_FOREVER_REL));
    GNUNET_assert (0 != block_size);
    block = GNUNET_malloc (block_size);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_HELLO_builder_to_block (b,
                                                  &priv,
                                                  block,
                                                  &block_size,
                                                  GNUNET_TIME_UNIT_FOREVER_REL));
    b2 = GNUNET_HELLO_builder_from_block (block,
                                          block_size);
    GNUNET_free (block);
    GNUNET_assert (NULL != b2);
    found = 0;
    p2 = GNUNET_HELLO_builder_iterate (b2,
                                       &check_uris,
                                       &found);
    GNUNET_assert (3 == found);
    GNUNET_assert (0 ==
                   GNUNET_memcmp (p2,
                                  &pid));
    GNUNET_HELLO_builder_free (b2);
  }

  {
    char *url;
    struct GNUNET_HELLO_Builder *b2;
    const struct GNUNET_PeerIdentity *p2;
    unsigned int found;

    url = GNUNET_HELLO_builder_to_url (b,
                                       &priv);
    b2 = GNUNET_HELLO_builder_from_url (url);
    GNUNET_free (url);
    GNUNET_assert (NULL != b2);
    found = 0;
    p2 = GNUNET_HELLO_builder_iterate (b2,
                                       &check_uris,
                                       &found);
    GNUNET_assert (3 == found);
    GNUNET_assert (0 ==
                   GNUNET_memcmp (p2,
                                  &pid));
    GNUNET_HELLO_builder_free (b2);
  }

  {
    struct GNUNET_MQ_Envelope *env;
    struct GNUNET_HELLO_Builder *b2;
    const struct GNUNET_PeerIdentity *p2;
    unsigned int found;

    env = GNUNET_HELLO_builder_to_env (b,
                                       &priv,
                                       GNUNET_TIME_UNIT_FOREVER_REL);
    b2 = GNUNET_HELLO_builder_from_msg (GNUNET_MQ_env_get_msg (env));
    GNUNET_free (env);
    GNUNET_assert (NULL != b2);
    found = 0;
    p2 = GNUNET_HELLO_builder_iterate (b2,
                                       &check_uris,
                                       &found);
    GNUNET_assert (3 == found);
    GNUNET_assert (0 ==
                   GNUNET_memcmp (p2,
                                  &pid));
    GNUNET_HELLO_builder_free (b2);
  }

  GNUNET_HELLO_builder_free (b);

  GNUNET_CRYPTO_mpi_print_unsigned (priv.d,
                                    sizeof (priv.d),
                                    GCRYMPI_CONST_ONE);
  priv.d[0] &= 248;
  priv.d[31] &= 127;
  priv.d[31] |= 64;
  {
    char *buf;

    buf = GNUNET_STRINGS_data_to_string_alloc (&priv,
                                               sizeof (priv));
    fprintf (stderr,
             "PK: %s\n",
             buf);
    GNUNET_free (buf);
  }
  GNUNET_CRYPTO_eddsa_key_get_public (&priv,
                                      &pid.public_key);
  b = GNUNET_HELLO_builder_new (&pid);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_builder_add_address (b,
                                                   "a://first"));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_builder_add_address (b,
                                                   "b://second"));
  {
    char *url;

    url = GNUNET_HELLO_builder_to_url (b,
                                       &priv);
    fprintf (stderr,
             "TV: %s\n",
             url);
    GNUNET_free (url);
  }
  GNUNET_HELLO_builder_free (b);

  return 0;
}
