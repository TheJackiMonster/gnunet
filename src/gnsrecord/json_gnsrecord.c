/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013 GNUnet e.V.

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
 * @file json/json_gnsrecord.c
 * @brief JSON handling of GNS record data
 * @author Philippe Buschmann
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_json_lib.h"
#include "gnunet_gnsrecord_lib.h"

#define GNUNET_JSON_GNSRECORD_VALUE "value"
#define GNUNET_JSON_GNSRECORD_RECORD_DATA "data"
#define GNUNET_JSON_GNSRECORD_TYPE "record_type"
#define GNUNET_JSON_GNSRECORD_RELATIVE_EXPIRATION_TIME "relative_expiration"
#define GNUNET_JSON_GNSRECORD_ABSOLUTE_EXPIRATION_TIME "absolute_expiration"
#define GNUNET_JSON_GNSRECORD_FLAG_PRIVATE "is_private"
#define GNUNET_JSON_GNSRECORD_FLAG_SUPPLEMENTAL "is_supplemental"
#define GNUNET_JSON_GNSRECORD_FLAG_RELATIVE "is_relative_expiration"
#define GNUNET_JSON_GNSRECORD_FLAG_SHADOW "is_shadow"
#define GNUNET_JSON_GNSRECORD_RECORD_NAME "record_name"

struct GnsRecordInfo
{
  char **name;

  unsigned int *rd_count;

  struct GNUNET_GNSRECORD_Data **rd;
};


static void
cleanup_recordinfo (struct GnsRecordInfo *gnsrecord_info)
{
  char *tmp;

  if (NULL != *(gnsrecord_info->rd))
  {
    for (int i = 0; i < *(gnsrecord_info->rd_count); i++)
    {
      tmp = (char*) (*(gnsrecord_info->rd))[i].data;
      if (NULL != tmp)
        GNUNET_free (tmp);
    }
    GNUNET_free (*(gnsrecord_info->rd));
    *(gnsrecord_info->rd) = NULL;
  }
  if (NULL != *(gnsrecord_info->name))
    GNUNET_free (*(gnsrecord_info->name));
  *(gnsrecord_info->name) = NULL;
}


/**
 * Parse given JSON object to gns record
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_record (json_t *data, struct GNUNET_GNSRECORD_Data *rd)
{
  struct GNUNET_TIME_Absolute abs_exp;
  struct GNUNET_TIME_Relative rel_exp;
  const char *value;
  const char *record_type;
  int private;
  int supplemental;
  int is_rel_exp;
  int shadow;
  int unpack_state = 0;
  json_error_t err;

  // interpret single gns record
  unpack_state = json_unpack_ex (data,
                                 &err,
                                 0,
                                 "{s:s, s:s, s:i, s:b, s:b, s:b, s:b}",
                                 GNUNET_JSON_GNSRECORD_VALUE,
                                 &value,
                                 GNUNET_JSON_GNSRECORD_TYPE,
                                 &record_type,
                                 GNUNET_JSON_GNSRECORD_RELATIVE_EXPIRATION_TIME,
                                 &rel_exp.rel_value_us,
                                 GNUNET_JSON_GNSRECORD_FLAG_PRIVATE,
                                 &private,
                                 GNUNET_JSON_GNSRECORD_FLAG_SUPPLEMENTAL,
                                 &supplemental,
                                 GNUNET_JSON_GNSRECORD_FLAG_RELATIVE,
                                 &is_rel_exp,
                                 GNUNET_JSON_GNSRECORD_FLAG_SHADOW,
                                 &shadow);
  if (0 != unpack_state)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Error gnsdata object has a wrong format: `%s'!\n",
                  err.text);
    unpack_state = json_unpack_ex (data,
                                   &err,
                                   0,
                                   "{s:s, s:s, s:I, s:b, s:b, s:b, s:b}",
                                   GNUNET_JSON_GNSRECORD_VALUE,
                                   &value,
                                   GNUNET_JSON_GNSRECORD_TYPE,
                                   &record_type,
                                   GNUNET_JSON_GNSRECORD_ABSOLUTE_EXPIRATION_TIME,
                                   &abs_exp.abs_value_us,
                                   GNUNET_JSON_GNSRECORD_FLAG_PRIVATE,
                                   &private,
                                   GNUNET_JSON_GNSRECORD_FLAG_SUPPLEMENTAL,
                                   &supplemental,
                                   GNUNET_JSON_GNSRECORD_FLAG_RELATIVE,
                                   &is_rel_exp,
                                   GNUNET_JSON_GNSRECORD_FLAG_SHADOW,
                                   &shadow);
    if ((0 != unpack_state) || (is_rel_exp))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Error gnsdata object has a wrong format: `%s'!\n",
                  (is_rel_exp) ? "No relative expiration given" : err.text);
      return GNUNET_SYSERR;
    }
    rd->expiration_time = abs_exp.abs_value_us;
  } else {
    rd->expiration_time = rel_exp.rel_value_us;
  }
  rd->record_type = GNUNET_GNSRECORD_typename_to_number (record_type);
  if (UINT32_MAX == rd->record_type)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Unsupported type\n");
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK != GNUNET_GNSRECORD_string_to_value (rd->record_type,
                                                     value,
                                                     (void **) &rd->data,
                                                     &rd->data_size))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Value invalid for record type\n");
    return GNUNET_SYSERR;
  }

  if (is_rel_exp)
    rd->flags |= GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  if (1 == private)
    rd->flags |= GNUNET_GNSRECORD_RF_PRIVATE;
  if (1 == supplemental)
    rd->flags |= GNUNET_GNSRECORD_RF_SUPPLEMENTAL;
  if (1 == shadow)
    rd->flags |= GNUNET_GNSRECORD_RF_SHADOW_RECORD;
  return GNUNET_OK;
}


/**
 * Parse given JSON object to gns record
 *
 * @param cls closure, NULL
 * @param root the json object representing data
 * @param spec where to write the data
 * @return #GNUNET_OK upon successful parsing; #GNUNET_SYSERR upon error
 */
static int
parse_record_data (struct GnsRecordInfo *gnsrecord_info, json_t *data)
{
  GNUNET_assert (NULL != data);
  if (! json_is_array (data))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error gns record data JSON is not an array!\n");
    return GNUNET_SYSERR;
  }
  *(gnsrecord_info->rd_count) = json_array_size (data);
  *(gnsrecord_info->rd) = GNUNET_malloc (sizeof(struct GNUNET_GNSRECORD_Data)
                                         * json_array_size (data));
  size_t index;
  json_t *value;
  json_array_foreach (data, index, value)
  {
    if (GNUNET_OK != parse_record (value, &(*(gnsrecord_info->rd))[index]))
      return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


static int
parse_gnsrecordobject (void *cls,
                       json_t *root,
                       struct GNUNET_JSON_Specification *spec)
{
  struct GnsRecordInfo *gnsrecord_info;
  int unpack_state = 0;
  const char *name;
  json_t *data;

  GNUNET_assert (NULL != root);
  if (! json_is_object (root))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error record JSON is not an object!\n");
    return GNUNET_SYSERR;
  }
  // interpret single gns record
  unpack_state = json_unpack (root,
                              "{s:s, s:o!}",
                              GNUNET_JSON_GNSRECORD_RECORD_NAME,
                              &name,
                              GNUNET_JSON_GNSRECORD_RECORD_DATA,
                              &data);
  if (0 != unpack_state)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error namestore records object has a wrong format!\n");
    return GNUNET_SYSERR;
  }
  gnsrecord_info = (struct GnsRecordInfo *) spec->ptr;
  *(gnsrecord_info->name) = GNUNET_strdup (name);
  if (GNUNET_OK != parse_record_data (gnsrecord_info, data))
  {
    cleanup_recordinfo (gnsrecord_info);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Cleanup data left from parsing the record.
 *
 * @param cls closure, NULL
 * @param[out] spec where to free the data
 */
static void
clean_gnsrecordobject (void *cls, struct GNUNET_JSON_Specification *spec)
{
  struct GnsRecordInfo *gnsrecord_info = (struct GnsRecordInfo *) spec->ptr;

  GNUNET_free (gnsrecord_info);
}


/**
 * JSON Specification for GNS Records.
 *
 * @param gnsrecord_object struct of GNUNET_GNSRECORD_Data to fill
 * @return JSON Specification
 */
struct GNUNET_JSON_Specification
GNUNET_GNSRECORD_JSON_spec_gnsrecord (struct GNUNET_GNSRECORD_Data **rd,
                                      unsigned int *rd_count,
                                      char **name)
{
  struct GnsRecordInfo *gnsrecord_info = GNUNET_new (struct GnsRecordInfo);

  gnsrecord_info->rd = rd;
  gnsrecord_info->name = name;
  gnsrecord_info->rd_count = rd_count;
  struct GNUNET_JSON_Specification ret = { .parser = &parse_gnsrecordobject,
                                           .cleaner = &clean_gnsrecordobject,
                                           .cls = NULL,
                                           .field = NULL,
                                           .ptr = (struct GnsRecordInfo *)
                                                  gnsrecord_info,
                                           .ptr_size = 0,
                                           .size_ptr = NULL };
  return ret;
}


/**
 * Convert GNS record to JSON.
 *
 * @param rname name of record
 * @param rd record data
 * @return corresponding JSON encoding
 */
json_t *
GNUNET_GNSRECORD_JSON_from_gnsrecord (const char*rname,
                                      const struct GNUNET_GNSRECORD_Data *rd,
                                      unsigned int rd_count)
{
  const char *record_type_str;
  char *value_str;
  json_t *data;
  json_t *record;
  json_t *records;

  data = json_object ();
  if (NULL == data)
  {
    GNUNET_break (0);
    return NULL;
  }
  if (0 !=
      json_object_set_new (data,
                           "record_name",
                           json_string (rname)))
  {
    GNUNET_break (0);
    json_decref (data);
    return NULL;
  }
  records = json_array ();
  if (NULL == records)
  {
    GNUNET_break (0);
    json_decref (data);
    return NULL;
  }
  for (int i = 0; i < rd_count; i++)
  {
    value_str = GNUNET_GNSRECORD_value_to_string (rd[i].record_type,
                                                  rd[i].data,
                                                  rd[i].data_size);
    record_type_str = GNUNET_GNSRECORD_number_to_typename (rd[i].record_type);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Packing %s %s %lu %d\n",
                value_str, record_type_str, rd[i].expiration_time, rd[i].flags);
    record = json_pack ("{s:s,s:s,s:I,s:b,s:b,s:b,s:b}",
                        GNUNET_JSON_GNSRECORD_VALUE,
                        value_str,
                        GNUNET_JSON_GNSRECORD_TYPE,
                        record_type_str,
                        (rd[i].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION) ?
                        GNUNET_JSON_GNSRECORD_RELATIVE_EXPIRATION_TIME : GNUNET_JSON_GNSRECORD_ABSOLUTE_EXPIRATION_TIME,
                        rd[i].expiration_time,
                        GNUNET_JSON_GNSRECORD_FLAG_PRIVATE,
                        rd[i].flags & GNUNET_GNSRECORD_RF_PRIVATE,
                        GNUNET_JSON_GNSRECORD_FLAG_RELATIVE,
                        rd[i].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION,
                        GNUNET_JSON_GNSRECORD_FLAG_SUPPLEMENTAL,
                        rd[i].flags & GNUNET_GNSRECORD_RF_SUPPLEMENTAL,
                        GNUNET_JSON_GNSRECORD_FLAG_SUPPLEMENTAL,
                        rd[i].flags & GNUNET_GNSRECORD_RF_SHADOW_RECORD);
    GNUNET_free (value_str);
    if (NULL == record)
    {
      GNUNET_break (0);
      json_decref (records);
      json_decref (data);
      return NULL;
    }
    if (0 !=
        json_array_append_new (records,
                               record))
    {
      GNUNET_break (0);
      json_decref (records);
      json_decref (data);
      return NULL;
    }
  }
  if (0 !=
      json_object_set_new (data,
                           "data",
                           records))
  {
    GNUNET_break (0);
    json_decref (data);
    return NULL;
  }
  return data;
}
