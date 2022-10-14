/*
   This file is part of GNUnet
   Copyright (C) 2017, 2019 GNUnet e.V.

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
 * @file pq/pq_prepare.c
 * @brief functions to connect to libpq (PostGres)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "pq.h"


struct GNUNET_PQ_PreparedStatement
GNUNET_PQ_make_prepare (const char *name,
                        const char *sql)
{
  struct GNUNET_PQ_PreparedStatement ps = {
    .name = name,
    .sql = sql
  };

  return ps;
}


enum GNUNET_GenericReturnValue
GNUNET_PQ_prepare_once (struct GNUNET_PQ_Context *db,
                        const struct GNUNET_PQ_PreparedStatement *ps)
{
  for (unsigned int i = 0; NULL != ps[i].name; i++)
  {
    PGresult *ret;

    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                     "pq",
                     "Preparing SQL statement `%s' as `%s'\n",
                     ps[i].sql,
                     ps[i].name);
    ret = PQprepare (db->conn,
                     ps[i].name,
                     ps[i].sql,
                     0,
                     NULL);
    if (PGRES_COMMAND_OK != PQresultStatus (ret))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                       "pq",
                       "PQprepare (`%s' as `%s') failed with error: %s\n",
                       ps[i].sql,
                       ps[i].name,
                       PQerrorMessage (db->conn));
      PQclear (ret);
      ret = PQdescribePrepared (db->conn,
                                ps[i].name);
      if (PGRES_COMMAND_OK != PQresultStatus (ret))
      {
        PQclear (ret);
        return GNUNET_SYSERR;
      }
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                       "pq",
                       "Statement `%s' already known. Ignoring the issue in the hope that you are using connection pooling...\n",
                       ps[i].name);
    }
    PQclear (ret);
  }
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_PQ_prepare_statements (struct GNUNET_PQ_Context *db,
                              const struct GNUNET_PQ_PreparedStatement *ps)
{
  if (db->ps != ps)
  {
    /* add 'ps' to list db->ps of prepared statements to run on reconnect! */
    unsigned int nlen = 0; /* length of 'ps' array */
    unsigned int xlen;
    struct GNUNET_PQ_PreparedStatement *rps; /* combined array */

    while (NULL != ps[nlen].name)
      nlen++;
    xlen = nlen + db->ps_off;
    if (xlen > db->ps_len)
    {
      xlen = 2 * xlen + 1;
      rps = GNUNET_new_array (xlen,
                              struct GNUNET_PQ_PreparedStatement);
      if (NULL != db->ps)
        memcpy (rps,
                db->ps,
                db->ps_off * sizeof (struct GNUNET_PQ_PreparedStatement));
      GNUNET_free (db->ps);
      db->ps_len = xlen;
      db->ps = rps;
    }
    memcpy (&db->ps[db->ps_off],
            ps,
            nlen * sizeof (struct GNUNET_PQ_PreparedStatement));
    db->ps_off += nlen;
  }

  return GNUNET_PQ_prepare_once (db,
                                 ps);
}


/* end of pq/pq_prepare.c */
