/*
   This file is part of GNUnet
   Copyright (C) 2014, 2015, 2016, 2017, 2019, 2020 GNUnet e.V.

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
 * @file pq/pq.c
 * @brief helper functions for libpq (PostGres) interactions
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 * @author Florian Dold
 * @author Christian Grothoff
 */
#include "platform.h"
#include "pq.h"


PGresult *
GNUNET_PQ_exec_prepared (struct GNUNET_PQ_Context *db,
                         const char *name,
                         const struct GNUNET_PQ_QueryParam *params)
{
  unsigned int len;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Running prepared statement `%s' on %p\n",
              name,
              db);
  /* count the number of parameters */
  len = 0;
  for (unsigned int i = 0; 0 != params[i].num_params; i++)
    len += params[i].num_params;

  /* new scope to allow stack allocation without alloca */
  {
    /* Scratch buffer for temporary storage */
    void *scratch[len];
    /* Parameter array we are building for the query */
    void *param_values[len];
    int param_lengths[len];
    int param_formats[len];
    unsigned int off;
    /* How many entries in the scratch buffer are in use? */
    unsigned int soff;
    PGresult *res;
    int ret;
    ConnStatusType status;

    off = 0;
    soff = 0;
    for (unsigned int i = 0; 0 != params[i].num_params; i++)
    {
      const struct GNUNET_PQ_QueryParam *x = &params[i];

      ret = x->conv (x->conv_cls,
                     x->data,
                     x->size,
                     &param_values[off],
                     &param_lengths[off],
                     &param_formats[off],
                     x->num_params,
                     &scratch[soff],
                     len - soff);
      if (ret < 0)
      {
        for (off = 0; off < soff; off++)
          GNUNET_free (scratch[off]);
        return NULL;
      }
      soff += ret;
      off += x->num_params;
    }
    GNUNET_assert (off == len);
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                     "pq",
                     "Executing prepared SQL statement `%s'\n",
                     name);
    res = PQexecPrepared (db->conn,
                          name,
                          len,
                          (const char **) param_values,
                          param_lengths,
                          param_formats,
                          1);
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                     "pq",
                     "Execution of prepared SQL statement `%s' finished (%d)\n",
                     name,
                     PGRES_COMMAND_OK == PQresultStatus (res));
    if ( (PGRES_COMMAND_OK != PQresultStatus (res)) &&
         (CONNECTION_OK != (status = PQstatus (db->conn))) )
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "pq",
                       "Database disconnected on SQL statement `%s' (reconnecting)\n",
                       name);
      GNUNET_PQ_reconnect (db);
      res = NULL;
    }

    for (off = 0; off < soff; off++)
      GNUNET_free (scratch[off]);
    return res;
  }
}


void
GNUNET_PQ_cleanup_result (struct GNUNET_PQ_ResultSpec *rs)
{
  for (unsigned int i = 0; NULL != rs[i].conv; i++)
    if (NULL != rs[i].cleaner)
      rs[i].cleaner (rs[i].cls,
                     rs[i].dst);
}


enum GNUNET_GenericReturnValue
GNUNET_PQ_extract_result (PGresult *result,
                          struct GNUNET_PQ_ResultSpec *rs,
                          int row)
{
  unsigned int i;

  if (NULL == result)
    return GNUNET_SYSERR;
  for (i = 0; NULL != rs[i].conv; i++)
  {
    struct GNUNET_PQ_ResultSpec *spec;
    enum GNUNET_GenericReturnValue ret;

    spec = &rs[i];
    ret = spec->conv (spec->cls,
                      result,
                      row,
                      spec->fname,
                      &spec->dst_size,
                      spec->dst);
    switch (ret)
    {
    case GNUNET_OK:
      /* canonical case, continue below */
      if (NULL != spec->is_null)
        *spec->is_null = false;
      break;
    case GNUNET_NO:
      if (spec->is_nullable)
      {
        if (NULL != spec->is_null)
          *spec->is_null = true;
        continue;
      }
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "NULL field encountered for `%s' where non-NULL was required\n",
                  spec->fname);
      goto cleanup;
    case GNUNET_SYSERR:
      GNUNET_break (0);
      goto cleanup;
    }
    if (NULL != spec->result_size)
      *spec->result_size = spec->dst_size;
  }
  return GNUNET_OK;
cleanup:
  for (unsigned int j = 0; j < i; j++)
    if (NULL != rs[j].cleaner)
      rs[j].cleaner (rs[j].cls,
                     rs[j].dst);
  return GNUNET_SYSERR;
}


/* end of pq/pq.c */
