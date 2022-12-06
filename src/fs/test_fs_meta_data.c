/*
     This file is part of GNUnet.
     Copyright (C) 2003, 2004, 2006, 2009, 2010, 2022 GNUnet e.V.

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
 * @file util/test_fs_meta_data.c
 * @brief Test for fs_meta_data.c
 * @author Christian Grothoff
 * @author Martin Schanzenbach
 */


#include "platform.h"
#include "gnunet_util_lib.h"

#include "gnunet_fs_service.h"

#define ABORT(m) { fprintf (stderr, "Error at %s:%d\n", __FILE__, __LINE__); \
                   if (m != NULL) GNUNET_FS_meta_data_destroy (m); \
                   return 1; }


static int
testMeta (int i)
{
  struct GNUNET_FS_MetaData *m;
  char val[256];
  char *sval;
  int j;
  unsigned int size;

  m = GNUNET_FS_meta_data_create ();
  if (GNUNET_OK !=
      GNUNET_FS_meta_data_insert (m, "<test>", EXTRACTOR_METATYPE_TITLE,
                                  EXTRACTOR_METAFORMAT_UTF8,
                                  "text/plain", "TestTitle",
                                  strlen ("TestTitle") + 1))
    ABORT (m);
  if (GNUNET_OK !=
      GNUNET_FS_meta_data_insert (m, "<test>",
                                  EXTRACTOR_METATYPE_AUTHOR_NAME,
                                  EXTRACTOR_METAFORMAT_UTF8,
                                  "text/plain", "TestTitle",
                                  strlen ("TestTitle") + 1))
    ABORT (m);
  if (GNUNET_OK == GNUNET_FS_meta_data_insert (m, "<test>",
                                               EXTRACTOR_METATYPE_TITLE,
                                               EXTRACTOR_METAFORMAT_UTF8,
                                               "text/plain",
                                               "TestTitle", strlen (
                                                 "TestTitle") + 1))                                                                                                             /* dup! */
    ABORT (m);
  if (GNUNET_OK == GNUNET_FS_meta_data_insert (m, "<test>",
                                               EXTRACTOR_METATYPE_AUTHOR_NAME,
                                               EXTRACTOR_METAFORMAT_UTF8,
                                               "text/plain",
                                               "TestTitle", strlen (
                                                 "TestTitle") + 1))                                                                                                                     /* dup! */
    ABORT (m);
  if (2 != GNUNET_FS_meta_data_iterate (m, NULL, NULL))
    ABORT (m);
  if (GNUNET_OK !=
      GNUNET_FS_meta_data_delete (m, EXTRACTOR_METATYPE_AUTHOR_NAME,
                                  "TestTitle", strlen ("TestTitle") + 1))
    ABORT (m);
  if (GNUNET_OK == GNUNET_FS_meta_data_delete (m,
                                               EXTRACTOR_METATYPE_AUTHOR_NAME,
                                               "TestTitle", strlen (
                                                 "TestTitle") + 1))                                                                     /* already gone */
    ABORT (m);
  if (1 != GNUNET_FS_meta_data_iterate (m, NULL, NULL))
    ABORT (m);
  if (GNUNET_OK !=
      GNUNET_FS_meta_data_delete (m, EXTRACTOR_METATYPE_TITLE,
                                  "TestTitle", strlen ("TestTitle") + 1))
    ABORT (m);
  if (GNUNET_OK == GNUNET_FS_meta_data_delete (m,
                                               EXTRACTOR_METATYPE_TITLE,
                                               "TestTitle", strlen (
                                                 "TestTitle") + 1))                                                             /* already gone */
    ABORT (m);
  if (0 != GNUNET_FS_meta_data_iterate (m, NULL, NULL))
    ABORT (m);
  for (j = 0; j < i; j++)
  {
    GNUNET_snprintf (val, sizeof(val), "%s.%d",
                     "A teststring that should compress well.", j);
    if (GNUNET_OK !=
        GNUNET_FS_meta_data_insert (m, "<test>",
                                    EXTRACTOR_METATYPE_UNKNOWN,
                                    EXTRACTOR_METAFORMAT_UTF8,
                                    "text/plain", val, strlen (val) + 1))
      ABORT (m);
  }
  if (i != GNUNET_FS_meta_data_iterate (m, NULL, NULL))
    ABORT (m);

  size = GNUNET_FS_meta_data_get_serialized_size (m);
  sval = NULL;
  if (size !=
      GNUNET_FS_meta_data_serialize (m, &sval, size,
                                     GNUNET_FS_META_DATA_SERIALIZE_FULL))
  {
    GNUNET_free (sval);
    ABORT (m);
  }
  GNUNET_FS_meta_data_destroy (m);
  m = GNUNET_FS_meta_data_deserialize (sval, size);
  GNUNET_free (sval);
  if (m == NULL)
    ABORT (m);
  for (j = 0; j < i; j++)
  {
    GNUNET_snprintf (val,
                     sizeof(val),
                     "%s.%d",
                     "A teststring that should compress well.",
                     j);
    if (GNUNET_OK !=
        GNUNET_FS_meta_data_delete (m,
                                    EXTRACTOR_METATYPE_UNKNOWN,
                                    val,
                                    strlen (val) + 1))
    {
      ABORT (m);
    }
  }
  if (0 != GNUNET_FS_meta_data_iterate (m, NULL, NULL))
    ABORT (m);
  GNUNET_FS_meta_data_destroy (m);
  return 0;
}


static int
testMetaMore (int i)
{
  struct GNUNET_FS_MetaData *meta;
  int q;
  char txt[128];
  char *data;
  unsigned long long size;

  meta = GNUNET_FS_meta_data_create ();
  for (q = 0; q <= i; q++)
  {
    GNUNET_snprintf (txt, 128, "%u -- %u\n", i, q);
    GNUNET_FS_meta_data_insert (meta, "<test>",
                                q
                                % 42 /* EXTRACTOR_metatype_get_max () */,
                                EXTRACTOR_METAFORMAT_UTF8, "text/plain",
                                txt, strlen (txt) + 1);
  }
  size = GNUNET_FS_meta_data_get_serialized_size (meta);
  data = GNUNET_malloc (size * 4);
  if (size !=
      GNUNET_FS_meta_data_serialize (meta, &data, size * 4,
                                     GNUNET_FS_META_DATA_SERIALIZE_FULL))
  {
    GNUNET_free (data);
    ABORT (meta);
  }
  GNUNET_FS_meta_data_destroy (meta);
  GNUNET_free (data);
  return 0;
}


static int
testMetaLink ()
{
  struct GNUNET_FS_MetaData *m;
  char *val;
  unsigned int size;

  m = GNUNET_FS_meta_data_create ();
  if (GNUNET_OK !=
      GNUNET_FS_meta_data_insert (m, "<test>",
                                  EXTRACTOR_METATYPE_UNKNOWN,
                                  EXTRACTOR_METAFORMAT_UTF8,
                                  "text/plain", "link",
                                  strlen ("link") + 1))
    ABORT (m);
  if (GNUNET_OK !=
      GNUNET_FS_meta_data_insert (m, "<test>",
                                  EXTRACTOR_METATYPE_FILENAME,
                                  EXTRACTOR_METAFORMAT_UTF8,
                                  "text/plain", "lib-link.m4",
                                  strlen ("lib-link.m4") + 1))
    ABORT (m);
  val = NULL;
  size =
    GNUNET_FS_meta_data_serialize (m, &val, (size_t) -1,
                                   GNUNET_FS_META_DATA_SERIALIZE_FULL);
  GNUNET_FS_meta_data_destroy (m);
  m = GNUNET_FS_meta_data_deserialize (val, size);
  GNUNET_free (val);
  if (m == NULL)
    ABORT (m);
  GNUNET_FS_meta_data_destroy (m);
  return 0;
}


static int
check ()
{
  struct GNUNET_FS_MetaData *meta;
  struct GNUNET_FS_MetaData *meta2;
  int q;
  int i = 100;
  char txt[128];
  char *str;
  unsigned char *thumb;

  meta = GNUNET_FS_meta_data_create ();
  meta2 = GNUNET_FS_meta_data_create ();
  for (q = 0; q <= i; q++)
  {
    GNUNET_snprintf (txt, 128, "%u -- %u\n", i, q);
    GNUNET_FS_meta_data_insert (meta, "<test>",
                                EXTRACTOR_METATYPE_UNKNOWN,
                                EXTRACTOR_METAFORMAT_UTF8, "text/plain",
                                "TestTitle", strlen ("TestTitle") + 1);
    GNUNET_FS_meta_data_insert (meta2, "<test>",
                                EXTRACTOR_METATYPE_UNKNOWN,
                                EXTRACTOR_METAFORMAT_UTF8, "text/plain",
                                "TestTitle", strlen ("TestTitle") + 1);
  }

  // check meta_data_test_equal
  if (GNUNET_YES != GNUNET_FS_meta_data_test_equal (meta, meta2))
  {
    GNUNET_FS_meta_data_destroy (meta2);
    ABORT (meta);
  }

  // check meta_data_clear
  GNUNET_FS_meta_data_clear (meta2);
  if (0 != GNUNET_FS_meta_data_iterate (meta2, NULL, NULL))
  {
    GNUNET_FS_meta_data_destroy (meta2);
    ABORT (meta);
  }
  // check equal branch in meta_data_test_equal
  if (GNUNET_YES != GNUNET_FS_meta_data_test_equal (meta, meta))
  {
    GNUNET_FS_meta_data_destroy (meta2);
    ABORT (meta);
  }
  // check "count" branch in meta_data_test_equal
  if (GNUNET_NO != GNUNET_FS_meta_data_test_equal (meta, meta2))
  {
    GNUNET_FS_meta_data_destroy (meta2);
    ABORT (meta);
  }

  // check meta_data_add_publication_date
  GNUNET_FS_meta_data_add_publication_date (meta2);

  // check meta_data_merge
  GNUNET_FS_meta_data_clear (meta2);
  GNUNET_FS_meta_data_merge (meta2, meta);
  if (100 == GNUNET_FS_meta_data_iterate (meta2, NULL, NULL))
  {
    GNUNET_FS_meta_data_destroy (meta2);
    ABORT (meta);
  }

  // check meta_data_get_by_type
  GNUNET_FS_meta_data_clear (meta2);
  if (NULL !=
      (str =
         GNUNET_FS_meta_data_get_by_type (meta2,
                                          EXTRACTOR_METATYPE_UNKNOWN)))
  {
    GNUNET_FS_meta_data_destroy (meta2);
    GNUNET_free (str);
    ABORT (meta);
  }

  str =
    GNUNET_FS_meta_data_get_by_type (meta, EXTRACTOR_METATYPE_UNKNOWN);
  GNUNET_assert (NULL != str);
  if (str[0] != 'T')
  {
    GNUNET_FS_meta_data_destroy (meta2);
    GNUNET_free (str);
    ABORT (meta);
  }
  GNUNET_free (str);

  // check branch
  if (NULL !=
      (str =
         GNUNET_FS_meta_data_get_by_type (meta,
                                          EXTRACTOR_METATYPE_PUBLICATION_DATE)))
  {
    GNUNET_free (str);
    GNUNET_FS_meta_data_destroy (meta2);
    ABORT (meta);
  }

  // check meta_data_get_first_by_types
  str =
    GNUNET_FS_meta_data_get_first_by_types (meta,
                                            EXTRACTOR_METATYPE_UNKNOWN,
                                            -1);
  GNUNET_assert (NULL != str);
  if (str[0] != 'T')
  {
    GNUNET_FS_meta_data_destroy (meta2);
    GNUNET_free (str);
    ABORT (meta);
  }
  GNUNET_free (str);

  // check meta_data_get_thumbnail
  if (GNUNET_FS_meta_data_get_thumbnail (meta, &thumb) != 0)
  {
    GNUNET_free (thumb);
    GNUNET_FS_meta_data_destroy (meta2);
    ABORT (meta);
  }
  GNUNET_FS_meta_data_destroy (meta2);
  // check meta_data_duplicate
  meta2 = GNUNET_FS_meta_data_duplicate (meta);
  if (200 == GNUNET_FS_meta_data_iterate (meta2, NULL, NULL))
  {
    GNUNET_FS_meta_data_destroy (meta2);
    ABORT (meta);
  }
  GNUNET_FS_meta_data_destroy (meta2);
  GNUNET_FS_meta_data_destroy (meta);
  return 0;
}


static int
test_bigmeta_rw (void)
{
  static char meta[1024 * 1024 * 10];
  struct GNUNET_BIO_WriteHandle *wh;
  struct GNUNET_BIO_ReadHandle *rh;
  char *filename = GNUNET_DISK_mktemp ("gnunet_bio");
  struct GNUNET_FS_MetaData *mdR = NULL;

  memset (meta, 'b', sizeof (meta));
  meta[sizeof (meta) - 1] = '\0';

  wh = GNUNET_BIO_write_open_file (filename);
  GNUNET_assert (NULL != wh);
  if (GNUNET_OK != GNUNET_BIO_write_int32 (wh,
                                           "test-bigmeta-rw-int32",
                                           sizeof (meta)))
  {
    GNUNET_BIO_write_close (wh, NULL);
    return 1;
  }
  if (GNUNET_OK != GNUNET_BIO_write (wh,
                                     "test-bigmeta-rw-bytes",
                                     meta,
                                     sizeof (meta)))
  {
    GNUNET_BIO_write_close (wh, NULL);
    return 1;
  }
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_close (wh, NULL));

  rh = GNUNET_BIO_read_open_file (filename);
  GNUNET_assert (NULL != rh);
  GNUNET_assert (GNUNET_SYSERR ==
                 GNUNET_FS_read_meta_data (rh,
                                           "test-bigmeta-rw-metadata",
                                           &mdR));
  GNUNET_assert (GNUNET_SYSERR == GNUNET_BIO_read_close (rh, NULL));

  GNUNET_assert (NULL == mdR);

  GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_remove (filename));
  GNUNET_free (filename);
  return 0;
}

static int
test_fakemeta_rw (void)
{
  struct GNUNET_BIO_WriteHandle *wh;
  struct GNUNET_BIO_ReadHandle *rh;
  char *filename = GNUNET_DISK_mktemp ("gnunet_bio");
  struct GNUNET_FS_MetaData *mdR = NULL;

  wh = GNUNET_BIO_write_open_file (filename);
  GNUNET_assert (NULL != wh);
  if (GNUNET_OK != GNUNET_BIO_write_int32 (wh,
                                           "test-fakestring-rw-int32",
                                           2))
  {
    GNUNET_BIO_write_close (wh, NULL);
    return 1;
  }
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_close (wh, NULL));

  rh = GNUNET_BIO_read_open_file (filename);
  GNUNET_assert (NULL != rh);
  GNUNET_assert (GNUNET_SYSERR ==
                 GNUNET_FS_read_meta_data (rh,
                                           "test-fakestring-rw-metadata",
                                           &mdR));
  GNUNET_assert (GNUNET_SYSERR == GNUNET_BIO_read_close (rh, NULL));

  GNUNET_assert (NULL == mdR);

  GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_remove (filename));
  GNUNET_free (filename);
  return 0;
}

static int
test_fakebigmeta_rw (void)
{
  struct GNUNET_BIO_WriteHandle *wh;
  struct GNUNET_BIO_ReadHandle *rh;
  char *filename = GNUNET_DISK_mktemp ("gnunet_bio");
  struct GNUNET_FS_MetaData *mdR = NULL;
  int32_t wNum = 1024 * 1024 * 10;

  wh = GNUNET_BIO_write_open_file (filename);
  GNUNET_assert (NULL != wh);
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_int32 (wh,
                                                      "test-fakebigmeta-rw-int32",
                                                      wNum));
  GNUNET_assert (GNUNET_OK == GNUNET_BIO_write_close (wh, NULL));

  rh = GNUNET_BIO_read_open_file (filename);
  GNUNET_assert (NULL != rh);
  GNUNET_assert (GNUNET_SYSERR ==
                 GNUNET_FS_read_meta_data (rh,
                                           "test-fakebigmeta-rw-metadata",
                                           &mdR));
  GNUNET_assert (GNUNET_SYSERR == GNUNET_BIO_read_close (rh, NULL));

  GNUNET_assert (NULL == mdR);

  GNUNET_assert (GNUNET_OK == GNUNET_DISK_directory_remove (filename));
  GNUNET_free (filename);
  return 0;
}

int
main (int argc, char *argv[])
{
  int failureCount = 0;
  int i;

  GNUNET_log_setup ("test-fs-meta-data", "WARNING", NULL);
  for (i = 0; i < 255; i++)
    failureCount += testMeta (i);
  for (i = 1; i < 255; i++)
    failureCount += testMetaMore (i);
  failureCount += testMetaLink ();
  failureCount += test_fakebigmeta_rw ();
  failureCount += test_fakemeta_rw ();
  failureCount +=  test_bigmeta_rw ();
  int ret = check ();

  if (ret == 1)
    return 1;

  if (failureCount != 0)
    return 1;
  return 0;
}


/* end of test_container_meta_data.c */
