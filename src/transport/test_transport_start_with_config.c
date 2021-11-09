/*
      This file is part of GNUnet
      Copyright (C) 2021 GNUnet e.V.

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
 * @file transport/test_transport_start_with_config.c
 * @brief Generic program to start testcases in an configurable topology.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_testing_netjail_lib.h"
#include "gnunet_util_lib.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)


int
main (int argc,
      char *const *argv)
{
  char *topology_data;
  char *topology_data_script;
  struct GNUNET_TESTING_NetjailTopology *topology;
  unsigned int read_file = GNUNET_YES;
  int ret;
  char *rest = NULL;
  char *token;
  size_t single_line_len;
  size_t data_len;

  GNUNET_log_setup ("test-netjail",
                    "DEBUG",
                    NULL);

  if (0 == strcmp ("-s", argv[1]))
  {
    data_len = strlen (argv[2]);
    topology_data = GNUNET_malloc (data_len);
    topology_data_script = GNUNET_malloc (data_len);
    token = strtok_r (argv[2], "\n", &rest);
    while (NULL != token)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "token1 %s\n",
                  token);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "token2 %s\n",
                  token);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "topology_data %s\n",
                  topology_data);
      strcat (topology_data_script, token);
      strcat (topology_data_script, " ");
      strcat (topology_data, token);
      strcat (topology_data, "\n");
      token = strtok_r (NULL, "\n", &rest);
    }
    single_line_len = strlen (topology_data);
    topology_data_script [single_line_len - 1] = '\0';
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "read from string\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "topology_data %s\n",
                topology_data);
    read_file = GNUNET_NO;
    topology = GNUNET_TESTING_get_topo_from_string (topology_data);
  }
  else
  {
    topology_data = argv[1];
    topology_data_script = argv[1];
    topology = GNUNET_TESTING_get_topo_from_file (topology_data);
  }

  struct GNUNET_TESTING_Command commands[] = {
    GNUNET_TESTING_cmd_netjail_start ("netjail-start",
                                      topology_data_script,
                                      &read_file),
    GNUNET_TESTING_cmd_netjail_start_testing_system ("netjail-start-testbed",
                                                     topology,
                                                     &read_file,
                                                     topology_data_script),
    GNUNET_TESTING_cmd_stop_testing_system ("stop-testbed",
                                            "netjail-start-testbed",
                                            topology),
    GNUNET_TESTING_cmd_netjail_stop ("netjail-stop",
                                     topology_data_script,
                                     &read_file),
    GNUNET_TESTING_cmd_end ()
  };

  ret = GNUNET_TESTING_main (commands,
                             TIMEOUT);

  if (0 == strcmp ("-s", argv[1]))
  {
    GNUNET_free (topology_data_script);
    GNUNET_free (topology_data);
  }
  GNUNET_TESTING_free_topology (topology);

  return ret;
}
