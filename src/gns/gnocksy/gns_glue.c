#include <stdio.h>
#include <string.h>

/*
 * Glue function to return the authoritative part
 * of a name. i.e. the site of origin
 *
 * @param name the name to process
 * @param auth pointer where the result is stored
 * @return 0 on success < 0 on failure
 */
int
gns_glue_get_auth ( char* name, char* auth )
{
  char cmd[1024];
  char line[1024];
  FILE *p;

  sprintf (cmd, "%s %s", "gnunet-gns -a", name);

  p = popen(cmd, "r");

  if (p != NULL)
  {
    while (fgets (line, sizeof(line), p) != NULL)
    {
      if (line[strlen(line)-1] == '\n')
      {
        line[strlen(line)-1] = '\0';
        strcpy (auth, line);
        return 0;
      }
    }

  }

  fclose (p);

  return -1;
}

/*
 * Glue function to return the short version of
 * a given name
 *
 * @param name the name to shorten
 * @param shortened pointer where the result will be stored
 * @return 0 on success < 0 on failure
 */
int
gns_glue_shorten ( char* name, char* shortened )
{
  char cmd[1024];
  char line[1024];
  FILE *p;

  sprintf (cmd, "%s %s", "gnunet-gns -r -s", name);

  p = popen(cmd, "r");

  if (p != NULL)
  {
    while (fgets (line, sizeof(line), p) != NULL)
    {
      if (line[strlen(line)-1] == '\n')
      {
        line[strlen(line)-1] = '\0';
        strcpy (shortened, line);
        return 0;
      }
    }

  }

  fclose (p);

  return -1;
}


/*
 * Glue function to expand .+ urls and shorted the
 * resulting name
 *
 * @param to_expand the .+ name to expand
 * @param host the site of origin
 * @param shortened the expanded and shortened result pointer
 */
int
gns_glue_expand_and_shorten( char* to_expand, char* host, char* shortened )
{
  char cmd[1024];
  char line[1024];
  FILE *p;
  char sorig[256];
  char expanded[256];

  sprintf (shortened, "%s%s", to_expand, host); //TODO this is a mockup
  return 0;

  sprintf (cmd, "%s %s", "gnunet-gns -a", host);

  p = popen(cmd, "r");

  if (p != NULL)
  {
    while (fgets (line, sizeof(line), p) != NULL)
    {
      if (line[strlen(line)-1] == '\n')
      {
        line[strlen(line)-1] = '\0';
        strcpy (sorig, line);
        return 0;
      }
    }

  }

  fclose (p);

  sprintf (expanded, "%s.%s", to_expand, sorig);
  
  sprintf (cmd, "%s %s", "gnunet-gns -r -s", expanded);
 
  p = popen(cmd, "r");

  if (p != NULL)
  {
    while (fgets (line, sizeof(line), p) != NULL)
    {
      if (line[strlen(line)-1] == '\n')
      {
        line[strlen(line)-1] = '\0';
        strcpy (shortened, line);
        return 0;
      }
    }

  }

  fclose (p);

  return -1;
}
