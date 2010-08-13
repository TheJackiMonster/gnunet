/*
     This file is part of GNUnet
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file datastore/plugin_datastore_mysql.c
 * @brief mysql-based datastore backend
 * @author Igor Wronsky
 * @author Christian Grothoff
 *
 * NOTE: This db module does NOT work with mysql prior to 4.1 since
 * it uses prepared statements.  MySQL 5.0.46 promises to fix a bug
 * in MyISAM that is causing us grief.  At the time of this writing,
 * that version is yet to be released.  In anticipation, the code
 * will use MyISAM with 5.0.46 (and higher).  If you run such a
 * version, please run "make check" to verify that the MySQL bug
 * was actually fixed in your version (and if not, change the
 * code below to use MyISAM for gn071).
 *
 * HIGHLIGHTS
 *
 * Pros
 * + On up-to-date hardware where mysql can be used comfortably, this
 *   module will have better performance than the other db choices
 *   (according to our tests).
 * + Its often possible to recover the mysql database from internal
 *   inconsistencies. The other db choices do not support repair!
 * Cons
 * - Memory usage (Comment: "I have 1G and it never caused me trouble")
 * - Manual setup
 *
 * MANUAL SETUP INSTRUCTIONS
 *
 * 1) in /etc/gnunet.conf, set
 *    <pre>
 *     [datastore]
 *     DATABASE = "mysql"
 *    </pre>
 * 2) Then access mysql as root,
 *    <pre>
 *
 *    $ mysql -u root -p
 *
 *    </pre>
 *    and do the following. [You should replace $USER with the username
 *    that will be running the gnunetd process].
 *    <pre>
 *
      CREATE DATABASE gnunet;
      GRANT select,insert,update,delete,create,alter,drop,create temporary tables
         ON gnunet.* TO $USER@localhost;
      SET PASSWORD FOR $USER@localhost=PASSWORD('$the_password_you_like');
      FLUSH PRIVILEGES;
 *
 *    </pre>
 * 3) In the $HOME directory of $USER, create a ".my.cnf" file
 *    with the following lines
 *    <pre>

      [client]
      user=$USER
      password=$the_password_you_like

 *    </pre>
 *
 * Thats it. Note that .my.cnf file is a security risk unless its on
 * a safe partition etc. The $HOME/.my.cnf can of course be a symbolic
 * link. Even greater security risk can be achieved by setting no
 * password for $USER.  Luckily $USER has only priviledges to mess
 * up GNUnet's tables, nothing else (unless you give him more,
 * of course).<p>
 *
 * 4) Still, perhaps you should briefly try if the DB connection
 *    works. First, login as $USER. Then use,
 *
 *    <pre>
 *    $ mysql -u $USER -p $the_password_you_like
 *    mysql> use gnunet;
 *    </pre>
 *
 *    If you get the message &quot;Database changed&quot; it probably works.
 *
 *    [If you get &quot;ERROR 2002: Can't connect to local MySQL server
 *     through socket '/tmp/mysql.sock' (2)&quot; it may be resolvable by
 *     &quot;ln -s /var/run/mysqld/mysqld.sock /tmp/mysql.sock&quot;
 *     so there may be some additional trouble depending on your mysql setup.]
 *
 * REPAIRING TABLES
 *
 * - Its probably healthy to check your tables for inconsistencies
 *   every now and then.
 * - If you get odd SEGVs on gnunetd startup, it might be that the mysql
 *   databases have been corrupted.
 * - The tables can be verified/fixed in two ways;
 *   1) by running mysqlcheck -A, or
 *   2) by executing (inside of mysql using the GNUnet database):
 *   mysql> REPAIR TABLE gn090;
 *   mysql> REPAIR TABLE gn072;
 *
 * PROBLEMS?
 *
 * If you have problems related to the mysql module, your best
 * friend is probably the mysql manual. The first thing to check
 * is that mysql is basically operational, that you can connect
 * to it, create tables, issue queries etc.
 *
 * TODO:
 * - use FOREIGN KEY for 'uid/vkey'
 * - consistent naming of uid/vkey
 */

#include "platform.h"
#include "plugin_datastore.h"
#include "gnunet_util_lib.h"
#include <mysql/mysql.h>

#define DEBUG_MYSQL GNUNET_NO

#define MAX_DATUM_SIZE 65536

/**
 * Maximum number of supported parameters for a prepared
 * statement.  Increase if needed.
 */
#define MAX_PARAM 16

/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define DIE_MYSQL(cmd, dbh) do { GNUNET_log(GNUNET_ERROR_TYPE_ERROR, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, mysql_error((dbh)->dbf)); abort(); } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_MYSQL(level, cmd, dbh) do { GNUNET_log(level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, mysql_error((dbh)->dbf)); } while(0);


/* warning, slighly crazy mysql statements ahead.  Essentially, MySQL does not handle
   "OR" very well, so we need to use UNION instead.  And UNION does not
   automatically apply a LIMIT on the outermost clause, so we need to
   repeat ourselves quite a bit.  All hail the performance gods (and thanks
   to #mysql on freenode) */
#define SELECT_IT_LOW_PRIORITY "(SELECT type,prio,anonLevel,expire,hash,vkey FROM gn090 FORCE INDEX(prio) WHERE (prio = ? AND vkey > ?) "\
                               "ORDER BY prio ASC,vkey ASC LIMIT 1) "				\
                               "UNION "\
                               "(SELECT type,prio,anonLevel,expire,hash,vkey FROM gn090 FORCE INDEX(prio) WHERE (prio > ? AND vkey != ?)"\
                               "ORDER BY prio ASC,vkey ASC LIMIT 1)"\
                               "ORDER BY prio ASC,vkey ASC LIMIT 1"

#define SELECT_IT_NON_ANONYMOUS "(SELECT type,prio,anonLevel,expire,hash,vkey FROM gn090 FORCE INDEX(prio) WHERE (prio = ? AND vkey < ?)"\
                                " AND anonLevel=0 ORDER BY prio DESC,vkey DESC LIMIT 1) "\
                                "UNION "\
                                "(SELECT type,prio,anonLevel,expire,hash,vkey FROM gn090 FORCE INDEX(prio) WHERE (prio < ? AND vkey != ?)"\
                                " AND anonLevel=0 ORDER BY prio DESC,vkey DESC LIMIT 1) "\
                                "ORDER BY prio DESC,vkey DESC LIMIT 1"

#define SELECT_IT_EXPIRATION_TIME "(SELECT type,prio,anonLevel,expire,hash,vkey FROM gn090 FORCE INDEX(expire) WHERE (expire = ? AND vkey > ?) "\
                                  "ORDER BY expire ASC,vkey ASC LIMIT 1) "\
                                  "UNION "\
                                  "(SELECT type,prio,anonLevel,expire,hash,vkey FROM gn090 FORCE INDEX(expire) WHERE (expire > ? AND vkey != ?) "\
                                  "ORDER BY expire ASC,vkey ASC LIMIT 1)"\
                                  "ORDER BY expire ASC,vkey ASC LIMIT 1"


#define SELECT_IT_MIGRATION_ORDER "(SELECT type,prio,anonLevel,expire,hash,vkey FROM gn090 FORCE INDEX(expire) WHERE (expire = ? AND vkey < ?)"\
                                  " AND expire > ? AND type!=3"\
                                  " ORDER BY expire DESC,vkey DESC LIMIT 1) "\
                                  "UNION "\
                                  "(SELECT type,prio,anonLevel,expire,hash,vkey FROM gn090 FORCE INDEX(expire) WHERE (expire < ? AND vkey != ?)"\
                                  " AND expire > ? AND type!=3"\
                                  " ORDER BY expire DESC,vkey DESC LIMIT 1)"\
                                  "ORDER BY expire DESC,vkey DESC LIMIT 1"

// #define SELECT_SIZE "SELECT SUM(BIT_LENGTH(value) DIV 8) FROM gn072"


struct GNUNET_MysqlStatementHandle
{
  struct GNUNET_MysqlStatementHandle *next;

  struct GNUNET_MysqlStatementHandle *prev;

  char *query;

  MYSQL_STMT *statement;

  int valid;

};

/**
 * Context for the universal iterator.
 */
struct NextRequestClosure;

/**
 * Type of a function that will prepare
 * the next iteration.
 *
 * @param cls closure
 * @param nc the next context; NULL for the last
 *         call which gives the callback a chance to
 *         clean up the closure
 * @return GNUNET_OK on success, GNUNET_NO if there are
 *         no more values, GNUNET_SYSERR on error
 */
typedef int (*PrepareFunction)(void *cls,
			       struct NextRequestClosure *nc);


struct NextRequestClosure
{
  struct Plugin *plugin;

  struct GNUNET_TIME_Absolute now;

  /**
   * Function to call to prepare the next
   * iteration.
   */
  PrepareFunction prep;

  /**
   * Closure for prep.
   */
  void *prep_cls;

  MYSQL_BIND rbind[6];

  unsigned int type;
  
  unsigned int iter_select;

  PluginIterator dviter;

  void *dviter_cls;

  unsigned int last_prio;

  unsigned long long last_expire;

  unsigned long long last_vkey;

  int end_it;
};


/**
 * Context for all functions in this plugin.
 */
struct Plugin 
{
  /**
   * Our execution environment.
   */
  struct GNUNET_DATASTORE_PluginEnvironment *env;

  MYSQL *dbf;
  
  struct GNUNET_MysqlStatementHandle *shead;

  struct GNUNET_MysqlStatementHandle *stail;

  /**
   * Filename of "my.cnf" (msyql configuration).
   */
  char *cnffile;

  /**
   * Closure of the 'next_task' (must be freed if 'next_task' is cancelled).
   */
  struct NextRequestClosure *next_task_nc;

  /**
   * Pending task with scheduler for running the next request.
   */
  GNUNET_SCHEDULER_TaskIdentifier next_task;

  /**
   * Statements dealing with gn072 table 
   */
#define SELECT_VALUE "SELECT value FROM gn072 WHERE vkey=?"
  struct GNUNET_MysqlStatementHandle *select_value;

#define DELETE_VALUE "DELETE FROM gn072 WHERE vkey=?"
  struct GNUNET_MysqlStatementHandle *delete_value;

#define INSERT_VALUE "INSERT INTO gn072 (value) VALUES (?)"
  struct GNUNET_MysqlStatementHandle *insert_value;

  /**
   * Statements dealing with gn090 table 
   */
#define INSERT_ENTRY "INSERT INTO gn090 (type,prio,anonLevel,expire,hash,vhash,vkey) VALUES (?,?,?,?,?,?,?)"
  struct GNUNET_MysqlStatementHandle *insert_entry;
  
#define DELETE_ENTRY_BY_VKEY "DELETE FROM gn090 WHERE vkey=?"
  struct GNUNET_MysqlStatementHandle *delete_entry_by_vkey;
  
#define SELECT_ENTRY_BY_HASH "SELECT type,prio,anonLevel,expire,hash,vkey FROM gn090 FORCE INDEX (hash_vkey) WHERE hash=? AND vkey > ? ORDER BY vkey ASC LIMIT 1 OFFSET ?"
  struct GNUNET_MysqlStatementHandle *select_entry_by_hash;
  
#define SELECT_ENTRY_BY_HASH_AND_VHASH "SELECT type,prio,anonLevel,expire,hash,vkey FROM gn090 FORCE INDEX (hash_vhash_vkey) WHERE hash=? AND vhash=? AND vkey > ? ORDER BY vkey ASC LIMIT 1 OFFSET ?"
  struct GNUNET_MysqlStatementHandle *select_entry_by_hash_and_vhash;

#define SELECT_ENTRY_BY_HASH_AND_TYPE "SELECT type,prio,anonLevel,expire,hash,vkey FROM gn090 FORCE INDEX (hash_vkey) WHERE hash=? AND vkey > ? AND type=? ORDER BY vkey ASC LIMIT 1 OFFSET ?"
  struct GNUNET_MysqlStatementHandle *select_entry_by_hash_and_type;
  
#define SELECT_ENTRY_BY_HASH_VHASH_AND_TYPE "SELECT type,prio,anonLevel,expire,hash,vkey FROM gn090 FORCE INDEX (hash_vhash_vkey) WHERE hash=? AND vhash=? AND vkey > ? AND type=? ORDER BY vkey ASC LIMIT 1 OFFSET ?"
  struct GNUNET_MysqlStatementHandle *select_entry_by_hash_vhash_and_type;
  
#define COUNT_ENTRY_BY_HASH "SELECT count(*) FROM gn090 FORCE INDEX (hash) WHERE hash=?"
  struct GNUNET_MysqlStatementHandle *count_entry_by_hash;

#define COUNT_ENTRY_BY_HASH_AND_VHASH "SELECT count(*) FROM gn090 FORCE INDEX (hash_vhash_vkey) WHERE hash=? AND vhash=?"
  struct GNUNET_MysqlStatementHandle *count_entry_by_hash_and_vhash;

#define COUNT_ENTRY_BY_HASH_AND_TYPE "SELECT count(*) FROM gn090 FORCE INDEX (hash) WHERE hash=? AND type=?"
  struct GNUNET_MysqlStatementHandle *count_entry_by_hash_and_type;

#define COUNT_ENTRY_BY_HASH_VHASH_AND_TYPE "SELECT count(*) FROM gn090 FORCE INDEX (hash_vhash) WHERE hash=? AND vhash=? AND type=?"
  struct GNUNET_MysqlStatementHandle *count_entry_by_hash_vhash_and_type;

#define UPDATE_ENTRY "UPDATE gn090 SET prio=prio+?,expire=IF(expire>=?,expire,?) WHERE vkey=?"
  struct GNUNET_MysqlStatementHandle *update_entry;

  struct GNUNET_MysqlStatementHandle *iter[4];

  /**
   * Size of the mysql database on disk.
   */
  unsigned long long content_size;

};


/**
 * Obtain the location of ".my.cnf".
 * @return NULL on error
 */
static char *
get_my_cnf_path (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *cnffile;
  char *home_dir;
  struct stat st;
#ifndef WINDOWS
  struct passwd *pw;
#endif
  int configured;

#ifndef WINDOWS
  pw = getpwuid (getuid ());
  if (!pw)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, 
			   "getpwuid");
      return NULL;
    }
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_have_value (cfg,
				       "datastore-mysql", "CONFIG"))
    {
      GNUNET_assert (GNUNET_OK == 
		     GNUNET_CONFIGURATION_get_value_filename (cfg,
							      "datastore-mysql", "CONFIG", &cnffile));
      configured = GNUNET_YES;
    }
  else
    {
      home_dir = GNUNET_strdup (pw->pw_dir);
#else
      home_dir = (char *) GNUNET_malloc (_MAX_PATH + 1);
      plibc_conv_to_win_path ("~/", home_dir);
#endif
      GNUNET_asprintf (&cnffile, "%s/.my.cnf", home_dir);
      GNUNET_free (home_dir);
      configured = GNUNET_NO;
    }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Trying to use file `%s' for MySQL configuration.\n"),
	      cnffile);
  if ((0 != STAT (cnffile, &st)) ||
      (0 != ACCESS (cnffile, R_OK)) || (!S_ISREG (st.st_mode)))
    {
      if (configured == GNUNET_YES)
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		    _("Could not access file `%s': %s\n"), cnffile,
		    STRERROR (errno));
      GNUNET_free (cnffile);
      return NULL;
    }
  return cnffile;
}



/**
 * Free a prepared statement.
 */
static void
prepared_statement_destroy (struct Plugin *plugin, 
			    struct GNUNET_MysqlStatementHandle
			    *s)
{
  GNUNET_CONTAINER_DLL_remove (plugin->shead,
			       plugin->stail,
			       s);
  if (s->valid)
    mysql_stmt_close (s->statement);
  GNUNET_free (s->query);
  GNUNET_free (s);
}


/**
 * Close database connection and all prepared statements (we got a DB
 * disconnect error).
 */
static int
iclose (struct Plugin *plugin)
{
  struct GNUNET_MysqlStatementHandle *spos;

  spos = plugin->shead;
  while (NULL != plugin->shead)
    prepared_statement_destroy (plugin,
				plugin->shead);
  if (plugin->dbf != NULL)
    {
      mysql_close (plugin->dbf);
      plugin->dbf = NULL;
    }
  return GNUNET_OK;
}


/**
 * Open the connection with the database (and initialize
 * our default options).
 *
 * @return GNUNET_OK on success
 */
static int
iopen (struct Plugin *ret)
{
  char *mysql_dbname;
  char *mysql_server;
  char *mysql_user;
  char *mysql_password;
  unsigned long long mysql_port;
  my_bool reconnect;
  unsigned int timeout;

  ret->dbf = mysql_init (NULL);
  if (ret->dbf == NULL)
    return GNUNET_SYSERR;
  if (ret->cnffile != NULL)
    mysql_options (ret->dbf, MYSQL_READ_DEFAULT_FILE, ret->cnffile);
  mysql_options (ret->dbf, MYSQL_READ_DEFAULT_GROUP, "client");
  reconnect = 0;
  mysql_options (ret->dbf, MYSQL_OPT_RECONNECT, &reconnect);
  mysql_options (ret->dbf,
                 MYSQL_OPT_CONNECT_TIMEOUT, (const void *) &timeout);
  mysql_options(ret->dbf, MYSQL_SET_CHARSET_NAME, "UTF8");
  timeout = 60; /* in seconds */
  mysql_options (ret->dbf, MYSQL_OPT_READ_TIMEOUT, (const void *) &timeout);
  mysql_options (ret->dbf, MYSQL_OPT_WRITE_TIMEOUT, (const void *) &timeout);
  mysql_dbname = NULL;
  if (GNUNET_YES == GNUNET_CONFIGURATION_have_value (ret->env->cfg,
						     "datastore-mysql", "DATABASE"))
    GNUNET_assert (GNUNET_OK == 
		   GNUNET_CONFIGURATION_get_value_string (ret->env->cfg,
							  "datastore-mysql", "DATABASE", 
							  &mysql_dbname));
  else
    mysql_dbname = GNUNET_strdup ("gnunet");
  mysql_user = NULL;
  if (GNUNET_YES == GNUNET_CONFIGURATION_have_value (ret->env->cfg,
						     "datastore-mysql", "USER"))
    {
      GNUNET_assert (GNUNET_OK == 
		    GNUNET_CONFIGURATION_get_value_string (ret->env->cfg,
							   "datastore-mysql", "USER", 
							   &mysql_user));
    }
  mysql_password = NULL;
  if (GNUNET_YES == GNUNET_CONFIGURATION_have_value (ret->env->cfg,
						     "datastore-mysql", "PASSWORD"))
    {
      GNUNET_assert (GNUNET_OK ==
		    GNUNET_CONFIGURATION_get_value_string (ret->env->cfg,
							   "datastore-mysql", "PASSWORD",
							   &mysql_password));
    }
  mysql_server = NULL;
  if (GNUNET_YES == GNUNET_CONFIGURATION_have_value (ret->env->cfg,
						     "datastore-mysql", "HOST"))
    {
      GNUNET_assert (GNUNET_OK == 
		    GNUNET_CONFIGURATION_get_value_string (ret->env->cfg,
							   "datastore-mysql", "HOST", 
							   &mysql_server));
    }
  mysql_port = 0;
  if (GNUNET_YES == GNUNET_CONFIGURATION_have_value (ret->env->cfg,
						     "datastore-mysql", "PORT"))
    {
      GNUNET_assert (GNUNET_OK ==
		    GNUNET_CONFIGURATION_get_value_number (ret->env->cfg, "datastore-mysql",
							   "PORT", &mysql_port));
    }

  GNUNET_assert (mysql_dbname != NULL);
  mysql_real_connect (ret->dbf, mysql_server, mysql_user, mysql_password,
                      mysql_dbname, (unsigned int) mysql_port, NULL,
		      CLIENT_IGNORE_SIGPIPE);
  GNUNET_free_non_null (mysql_server);
  GNUNET_free_non_null (mysql_user);
  GNUNET_free_non_null (mysql_password);
  GNUNET_free (mysql_dbname);
  if (mysql_error (ret->dbf)[0])
    {
      LOG_MYSQL (GNUNET_ERROR_TYPE_ERROR,
                 "mysql_real_connect", ret);
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}


/**
 * Run the given MySQL statement.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
run_statement (struct Plugin *plugin,
	       const char *statement)
{
  if ((NULL == plugin->dbf) && (GNUNET_OK != iopen (plugin)))
    return GNUNET_SYSERR;
  mysql_query (plugin->dbf, statement);
  if (mysql_error (plugin->dbf)[0])
    {
      LOG_MYSQL (GNUNET_ERROR_TYPE_ERROR,
                 "mysql_query", plugin);
      iclose (plugin);
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}


/**
 * Create a prepared statement.
 *
 * @return NULL on error
 */
static struct GNUNET_MysqlStatementHandle *
prepared_statement_create (struct Plugin *plugin, 
			   const char *statement)
{
  struct GNUNET_MysqlStatementHandle *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_MysqlStatementHandle));
  ret->query = GNUNET_strdup (statement);
  GNUNET_CONTAINER_DLL_insert (plugin->shead,
			       plugin->stail,
			       ret);
  return ret;
}


/**
 * Prepare a statement for running.
 *
 * @return GNUNET_OK on success
 */
static int
prepare_statement (struct Plugin *plugin, 
		   struct GNUNET_MysqlStatementHandle *ret)
{
  if (GNUNET_YES == ret->valid)
    return GNUNET_OK;
  if ((NULL == plugin->dbf) && 
      (GNUNET_OK != iopen (plugin)))
    return GNUNET_SYSERR;
  ret->statement = mysql_stmt_init (plugin->dbf);
  if (ret->statement == NULL)
    {
      iclose (plugin);
      return GNUNET_SYSERR;
    }
  if (mysql_stmt_prepare (ret->statement, 
			  ret->query,
			  strlen (ret->query)))
    {
      LOG_MYSQL (GNUNET_ERROR_TYPE_ERROR,
                 "mysql_stmt_prepare", 
		 plugin);
      mysql_stmt_close (ret->statement);
      ret->statement = NULL;
      iclose (plugin);
      return GNUNET_SYSERR;
    }
  ret->valid = GNUNET_YES;
  return GNUNET_OK;

}


/**
 * Bind the parameters for the given MySQL statement
 * and run it.
 *
 * @param s statement to bind and run
 * @param ap arguments for the binding
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
static int
init_params (struct Plugin *plugin,
	     struct GNUNET_MysqlStatementHandle *s,
	     va_list ap)
{
  MYSQL_BIND qbind[MAX_PARAM];
  unsigned int pc;
  unsigned int off;
  enum enum_field_types ft;

  pc = mysql_stmt_param_count (s->statement);
  if (pc > MAX_PARAM)
    {
      /* increase internal constant! */
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  memset (qbind, 0, sizeof (qbind));
  off = 0;
  ft = 0;
  while ((pc > 0) && (-1 != (ft = va_arg (ap, enum enum_field_types))))
    {
      qbind[off].buffer_type = ft;
      switch (ft)
        {
        case MYSQL_TYPE_FLOAT:
          qbind[off].buffer = va_arg (ap, float *);
          break;
        case MYSQL_TYPE_LONGLONG:
          qbind[off].buffer = va_arg (ap, unsigned long long *);
          qbind[off].is_unsigned = va_arg (ap, int);
          break;
        case MYSQL_TYPE_LONG:
          qbind[off].buffer = va_arg (ap, unsigned int *);
          qbind[off].is_unsigned = va_arg (ap, int);
          break;
        case MYSQL_TYPE_VAR_STRING:
        case MYSQL_TYPE_STRING:
        case MYSQL_TYPE_BLOB:
          qbind[off].buffer = va_arg (ap, void *);
          qbind[off].buffer_length = va_arg (ap, unsigned long);
          qbind[off].length = va_arg (ap, unsigned long *);
          break;
        default:
          /* unsupported type */
          GNUNET_break (0);
          return GNUNET_SYSERR;
        }
      pc--;
      off++;
    }
  if (!((pc == 0) && (ft != -1) && (va_arg (ap, int) == -1)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  if (mysql_stmt_bind_param (s->statement, qbind))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("`%s' failed at %s:%d with error: %s\n"),
		  "mysql_stmt_bind_param",
		  __FILE__, __LINE__, mysql_stmt_error (s->statement));
      iclose (plugin);
      return GNUNET_SYSERR;
    }
  if (mysql_stmt_execute (s->statement))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("`%s' failed at %s:%d with error: %s\n"),
		  "mysql_stmt_execute",
		  __FILE__, __LINE__, mysql_stmt_error (s->statement));
      iclose (plugin);
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

/**
 * Type of a callback that will be called for each
 * data set returned from MySQL.
 *
 * @param cls user-defined argument
 * @param num_values number of elements in values
 * @param values values returned by MySQL
 * @return GNUNET_OK to continue iterating, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_MysqlDataProcessor) (void *cls,
                                          unsigned int num_values,
                                          MYSQL_BIND * values);


/**
 * Run a prepared SELECT statement.
 *
 * @param result_size number of elements in results array
 * @param results pointer to already initialized MYSQL_BIND
 *        array (of sufficient size) for passing results
 * @param processor function to call on each result
 * @param processor_cls extra argument to processor
 * @param ... pairs and triplets of "MYSQL_TYPE_XXX" keys and their respective
 *        values (size + buffer-reference for pointers); terminated
 *        with "-1"
 * @return GNUNET_SYSERR on error, otherwise
 *         the number of successfully affected (or queried) rows
 */
static int
prepared_statement_run_select (struct Plugin *plugin,
			       struct GNUNET_MysqlStatementHandle
			       *s,
			       unsigned int result_size,
			       MYSQL_BIND * results,
			       GNUNET_MysqlDataProcessor
			       processor, void *processor_cls,
			       ...)
{
  va_list ap;
  int ret;
  unsigned int rsize;
  int total;

  if (GNUNET_OK != prepare_statement (plugin, s))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  va_start (ap, processor_cls);
  if (GNUNET_OK != init_params (plugin, s, ap))
    {
      GNUNET_break (0);
      va_end (ap);
      return GNUNET_SYSERR;
    }
  va_end (ap);
  rsize = mysql_stmt_field_count (s->statement);
  if (rsize > result_size)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  if (mysql_stmt_bind_result (s->statement, results))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("`%s' failed at %s:%d with error: %s\n"),
		  "mysql_stmt_bind_result",
		  __FILE__, __LINE__, mysql_stmt_error (s->statement));
      iclose (plugin);
      return GNUNET_SYSERR;
    }

  total = 0;
  while (1)
    {
      ret = mysql_stmt_fetch (s->statement);
      if (ret == MYSQL_NO_DATA)
        break;
      if (ret != 0)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      _("`%s' failed at %s:%d with error: %s\n"),
		      "mysql_stmt_fetch",
		      __FILE__, __LINE__, mysql_stmt_error (s->statement));
          iclose (plugin);
          return GNUNET_SYSERR;
        }
      if (processor != NULL)
        if (GNUNET_OK != processor (processor_cls, rsize, results))
          break;
      total++;
    }
  mysql_stmt_reset (s->statement);
  return total;
}


/**
 * Run a prepared statement that does NOT produce results.
 *
 * @param ... pairs and triplets of "MYSQL_TYPE_XXX" keys and their respective
 *        values (size + buffer-reference for pointers); terminated
 *        with "-1"
 * @param insert_id NULL or address where to store the row ID of whatever
 *        was inserted (only for INSERT statements!)
 * @return GNUNET_SYSERR on error, otherwise
 *         the number of successfully affected rows
 */
static int
prepared_statement_run (struct Plugin *plugin,
			struct GNUNET_MysqlStatementHandle *s,
			unsigned long long *insert_id, ...)
{
  va_list ap;
  int affected;

  if (GNUNET_OK != prepare_statement (plugin, s))
    return GNUNET_SYSERR;
  va_start (ap, insert_id);
  if (GNUNET_OK != init_params (plugin, s, ap))
    {
      va_end (ap);
      return GNUNET_SYSERR;
    }
  va_end (ap);
  affected = mysql_stmt_affected_rows (s->statement);
  if (NULL != insert_id)
    *insert_id = (unsigned long long) mysql_stmt_insert_id (s->statement);
  mysql_stmt_reset (s->statement);
  return affected;
}


/**
 * Delete an value from the gn072 table.
 *
 * @param vkey vkey identifying the value to delete
 * @return GNUNET_OK on success, GNUNET_NO if no such value exists, GNUNET_SYSERR on error
 */
static int
do_delete_value (struct Plugin *plugin,
		 unsigned long long vkey)
{
  int ret;

#if DEBUG_MYSQL
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Deleting value %llu from gn072 table\n",
	      vkey);
#endif
  ret = prepared_statement_run (plugin,
				plugin->delete_value,
				NULL,
				MYSQL_TYPE_LONGLONG,
				&vkey, GNUNET_YES, -1);
  if (ret > 0)
    {
      ret = GNUNET_OK;
    }
  else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  "Deleting value %llu from gn072 table failed\n",
		  vkey);
    }
  return ret;
}

/**
 * Insert a value into the gn072 table.
 *
 * @param value the value to insert
 * @param size size of the value
 * @param vkey vkey identifying the value henceforth (set)
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
do_insert_value (struct Plugin *plugin,
		 const void *value, unsigned int size,
                 unsigned long long *vkey)
{
  unsigned long length = size;
  int ret;

  ret = prepared_statement_run (plugin,
				plugin->insert_value,
				vkey,
				MYSQL_TYPE_BLOB,
				value, length, &length, -1);
  if (ret == GNUNET_OK)
    {
#if DEBUG_MYSQL
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Inserted value number %llu with length %u into gn072 table\n",
		  *vkey,
		  size);
#endif
    }
  else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  "Failed to insert %u byte value into gn072 table\n",
		  size);
    }
  return ret;
}

/**
 * Delete an entry from the gn090 table.
 *
 * @param vkey vkey identifying the entry to delete
 * @return GNUNET_OK on success, GNUNET_NO if no such value exists, GNUNET_SYSERR on error
 */
static int
do_delete_entry_by_vkey (struct Plugin *plugin,
			 unsigned long long vkey)
{
  int ret;

#if DEBUG_MYSQL
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Deleting value %llu from gn090 table\n",
	      vkey);
#endif
  ret = prepared_statement_run (plugin,
				plugin->delete_entry_by_vkey,
				NULL,
				MYSQL_TYPE_LONGLONG,
				&vkey, GNUNET_YES, -1);
  if (ret > 0)
    {
      ret = GNUNET_OK;
    }
  else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  "Deleting value %llu from gn090 table failed\n",
		  vkey);
    }
  return ret;
}

static int
return_ok (void *cls, unsigned int num_values, MYSQL_BIND * values)
{
  return GNUNET_OK;
}


static int
iterator_helper_prepare (void *cls,
			 struct NextRequestClosure *nrc)
{
  struct Plugin *plugin;
  int ret;

  if (nrc == NULL)
    return GNUNET_NO;
  plugin = nrc->plugin;
  ret = GNUNET_SYSERR;
  switch (nrc->iter_select)
    {
    case 0:
    case 1:
      ret = prepared_statement_run_select (plugin,
					   plugin->iter[nrc->iter_select],
					   6,
					   nrc->rbind,
					   &return_ok,
					   NULL,
					   MYSQL_TYPE_LONG,
					   &nrc->last_prio,
					   GNUNET_YES,
					   MYSQL_TYPE_LONGLONG,
					   &nrc->last_vkey,
					   GNUNET_YES,
					   MYSQL_TYPE_LONG,
					   &nrc->last_prio,
					   GNUNET_YES,
					   MYSQL_TYPE_LONGLONG,
					   &nrc->last_vkey,
					   GNUNET_YES, -1);
      break;
    case 2:
      ret = prepared_statement_run_select (plugin,
					   plugin->iter[nrc->iter_select],
					   6,
					   nrc->rbind,
					   &return_ok,
					   NULL,
					   MYSQL_TYPE_LONGLONG,
					   &nrc->last_expire,
					   GNUNET_YES,
					   MYSQL_TYPE_LONGLONG,
					   &nrc->last_vkey,
					   GNUNET_YES,
					   MYSQL_TYPE_LONGLONG,
					   &nrc->last_expire,
					   GNUNET_YES,
					   MYSQL_TYPE_LONGLONG,
					   &nrc->last_vkey,
					   GNUNET_YES, -1);
      break;
    case 3:
      ret = prepared_statement_run_select (plugin,
					   plugin->iter[nrc->iter_select],
					   6,
					   nrc->rbind,
					   &return_ok,
					   NULL,
					   MYSQL_TYPE_LONGLONG,
					   &nrc->last_expire,
					   GNUNET_YES,
					   MYSQL_TYPE_LONGLONG,
					   &nrc->last_vkey,
					   GNUNET_YES,
					   MYSQL_TYPE_LONGLONG,
					   &nrc->now.value,
					   GNUNET_YES,
					   MYSQL_TYPE_LONGLONG,
					   &nrc->last_expire,
					   GNUNET_YES,
					   MYSQL_TYPE_LONGLONG,
					   &nrc->last_vkey,
					   GNUNET_YES,
					   MYSQL_TYPE_LONGLONG,
					   &nrc->now.value,
					   GNUNET_YES, -1);
      break;
    default:
      GNUNET_assert (0);
    }
  return ret;
}


/**
 * Continuation of "mysql_next_request".
 *
 * @param next_cls the next context
 * @param tc the task context (unused)
 */
static void 
mysql_next_request_cont (void *next_cls,
			  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NextRequestClosure *nrc = next_cls;
  struct Plugin *plugin;
  int ret;
  unsigned int type;
  unsigned int priority;
  unsigned int anonymity;
  unsigned long long exp;
  unsigned long long vkey;
  unsigned long hashSize;
  GNUNET_HashCode key;
  struct GNUNET_TIME_Absolute expiration;
  unsigned long length;
  MYSQL_BIND *rbind; /* size 7 */
  MYSQL_BIND dbind[1];
  char datum[GNUNET_SERVER_MAX_MESSAGE_SIZE];

  plugin = nrc->plugin;
  plugin->next_task = GNUNET_SCHEDULER_NO_TASK;
  plugin->next_task_nc = NULL;

 AGAIN: 
  GNUNET_assert (nrc->plugin->next_task == GNUNET_SCHEDULER_NO_TASK);
  nrc->now = GNUNET_TIME_absolute_get ();
  hashSize = sizeof (GNUNET_HashCode);
  memset (nrc->rbind, 0, sizeof (nrc->rbind));
  rbind = nrc->rbind;
  rbind[0].buffer_type = MYSQL_TYPE_LONG;
  rbind[0].buffer = &type;
  rbind[0].is_unsigned = 1;
  rbind[1].buffer_type = MYSQL_TYPE_LONG;
  rbind[1].buffer = &priority;
  rbind[1].is_unsigned = 1;
  rbind[2].buffer_type = MYSQL_TYPE_LONG;
  rbind[2].buffer = &anonymity;
  rbind[2].is_unsigned = 1;
  rbind[3].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[3].buffer = &exp;
  rbind[3].is_unsigned = 1;
  rbind[4].buffer_type = MYSQL_TYPE_BLOB;
  rbind[4].buffer = &key;
  rbind[4].buffer_length = hashSize;
  rbind[4].length = &hashSize;
  rbind[5].buffer_type = MYSQL_TYPE_LONGLONG;
  rbind[5].buffer = &vkey;
  rbind[5].is_unsigned = GNUNET_YES;

  if ( (GNUNET_YES == nrc->end_it) ||
       (GNUNET_OK != nrc->prep (nrc->prep_cls,
				nrc)))
    goto END_SET;
  GNUNET_assert (nrc->plugin->next_task == GNUNET_SCHEDULER_NO_TASK);
  nrc->last_vkey = vkey;
  nrc->last_prio = priority;
  nrc->last_expire = exp;
  if ( (rbind[4].buffer_length != sizeof (GNUNET_HashCode)) ||
       (hashSize != sizeof (GNUNET_HashCode)) )
    {
      GNUNET_break (0);
      goto END_SET;
    }	  
#if DEBUG_MYSQL
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Found value %llu with prio %u, anon %u, expire %llu selecting from gn090 table\n",
	      vkey,	      
	      priority,
	      anonymity,
	      exp);
#endif
  /* now do query on gn072 */
  length = sizeof (datum);
  memset (dbind, 0, sizeof (dbind));
  dbind[0].buffer_type = MYSQL_TYPE_BLOB;
  dbind[0].buffer_length = length;
  dbind[0].length = &length;
  dbind[0].buffer = datum;
  ret = prepared_statement_run_select (plugin,
				       plugin->select_value,
				       1,
				       dbind,
				       &return_ok,
				       NULL,
				       MYSQL_TYPE_LONGLONG,
				       &vkey, GNUNET_YES, -1);
  GNUNET_break (ret <= 1);     /* should only have one rbind! */
  if (ret > 0)
    ret = GNUNET_OK;
  if (ret != GNUNET_OK) 
    {
      GNUNET_break (0);
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, 
		  _("Failed to obtain value %llu from table `%s'\n"),
		  vkey,
		  "gn072");
      goto AGAIN;
    }
  GNUNET_break (length <= sizeof(datum));
#if DEBUG_MYSQL
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Calling iterator with value `%s' number %llu of size %u with type %u, priority %u, anonymity %u and expiration %llu\n",
	      GNUNET_h2s (&key),
	      vkey,	      
	      length,
	      type,
	      priority,
	      anonymity,
	      exp);
#endif
  GNUNET_assert (nrc->plugin->next_task == GNUNET_SCHEDULER_NO_TASK);
  expiration.value = exp;
  ret = nrc->dviter (nrc->dviter_cls,
		     nrc,
		     &key,
		     length,
		     datum,
		     type,
		     priority,
		     anonymity,
		     expiration,
		     vkey);
  if (ret == GNUNET_SYSERR)
    {
      nrc->end_it = GNUNET_YES;
      return;
    }
  if (ret == GNUNET_NO)
    {
      do_delete_value (plugin, vkey);
      do_delete_entry_by_vkey (plugin, vkey);
      plugin->content_size -= length;
    }
  return;
 END_SET:
  /* call dviter with "end of set" */
  GNUNET_assert (nrc->plugin->next_task == GNUNET_SCHEDULER_NO_TASK);
  nrc->dviter (nrc->dviter_cls, 
	       NULL, NULL, 0, NULL, 0, 0, 0, 
	       GNUNET_TIME_UNIT_ZERO_ABS, 0);
  GNUNET_assert (nrc->plugin->next_task == GNUNET_SCHEDULER_NO_TASK);
  nrc->prep (nrc->prep_cls, NULL);
  GNUNET_assert (nrc->plugin->next_task == GNUNET_SCHEDULER_NO_TASK);
  GNUNET_free (nrc);
}


/**
 * Function invoked on behalf of a "PluginIterator"
 * asking the database plugin to call the iterator
 * with the next item.
 *
 * @param next_cls whatever argument was given
 *        to the PluginIterator as "next_cls".
 * @param end_it set to GNUNET_YES if we
 *        should terminate the iteration early
 *        (iterator should be still called once more
 *         to signal the end of the iteration).
 */
static void 
mysql_plugin_next_request (void *next_cls,
			   int end_it)
{
  struct NextRequestClosure *nrc = next_cls;

  if (GNUNET_YES == end_it)
    nrc->end_it = GNUNET_YES;
  nrc->plugin->next_task_nc = nrc;
  nrc->plugin->next_task = GNUNET_SCHEDULER_add_now (nrc->plugin->env->sched,
						     &mysql_next_request_cont,
						     nrc);
}  


/**
 * Iterate over the items in the datastore
 * using the given query to select and order
 * the items.
 *
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param iter never NULL
 * @param is_asc are we using ascending order?
 */
static void
iterateHelper (struct Plugin *plugin,
	       unsigned int type,
               int is_asc,
               unsigned int iter_select, 
	       PluginIterator dviter,
               void *dviter_cls)
{
  struct NextRequestClosure *nrc;

  nrc = GNUNET_malloc (sizeof (struct NextRequestClosure));
  nrc->plugin = plugin;
  nrc->type = type;  
  nrc->iter_select = iter_select;
  nrc->dviter = dviter;
  nrc->dviter_cls = dviter_cls;
  nrc->prep = &iterator_helper_prepare;
  if (is_asc)
    {
      nrc->last_prio = 0;
      nrc->last_vkey = 0;
      nrc->last_expire = 0;
    }
  else
    {
      nrc->last_prio = 0x7FFFFFFFL;
      nrc->last_vkey = 0x7FFFFFFFFFFFFFFFLL; /* MySQL only supports 63 bits */
      nrc->last_expire = 0x7FFFFFFFFFFFFFFFLL;       /* MySQL only supports 63 bits */
    }
  mysql_plugin_next_request (nrc, GNUNET_NO);
}


/**
 * Get an estimate of how much space the database is
 * currently using.
 *
 * @param cls our "struct Plugin*"
 * @return number of bytes used on disk
 */
static unsigned long long
mysql_plugin_get_size (void *cls)
{
  struct Plugin *plugin = cls;
  return plugin->content_size;
}


/**
 * Store an item in the datastore.
 *
 * @param cls closure
 * @param key key for the item
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param msg set to error message
 * @return GNUNET_OK on success
 */
static int
mysql_plugin_put (void *cls,
		  const GNUNET_HashCode * key,
		  uint32_t size,
		  const void *data,
		  enum GNUNET_BLOCK_Type type,
		  uint32_t priority,
		  uint32_t anonymity,
		  struct GNUNET_TIME_Absolute expiration,
		  char **msg)
{
  struct Plugin *plugin = cls;
  unsigned int itype = type;
  unsigned int ipriority = priority;
  unsigned int ianonymity = anonymity;
  unsigned long long lexpiration = expiration.value;
  unsigned long hashSize;
  unsigned long hashSize2;
  unsigned long long vkey;
  GNUNET_HashCode vhash;

  if (size > MAX_DATUM_SIZE)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  hashSize = sizeof (GNUNET_HashCode);
  hashSize2 = sizeof (GNUNET_HashCode);
  GNUNET_CRYPTO_hash (data, size, &vhash);
  if (GNUNET_OK != do_insert_value (plugin,
				    data, size, &vkey))
    return GNUNET_SYSERR;
  if (GNUNET_OK !=
      prepared_statement_run (plugin,
			      plugin->insert_entry,
			      NULL,
			      MYSQL_TYPE_LONG,
			      &itype,
			      GNUNET_YES,
			      MYSQL_TYPE_LONG,
			      &ipriority,
			      GNUNET_YES,
			      MYSQL_TYPE_LONG,
			      &ianonymity,
			      GNUNET_YES,
			      MYSQL_TYPE_LONGLONG,
			      &lexpiration,
			      GNUNET_YES,
			      MYSQL_TYPE_BLOB,
			      key,
			      hashSize,
			      &hashSize,
			      MYSQL_TYPE_BLOB,
			      &vhash,
			      hashSize2,
			      &hashSize2,
			      MYSQL_TYPE_LONGLONG,
			      &vkey, GNUNET_YES, -1))
    {
      do_delete_value (plugin, vkey);
      return GNUNET_SYSERR;
    }
#if DEBUG_MYSQL
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Inserted value `%s' number %llu with size %u into gn090 table\n",
	      GNUNET_h2s (key),
	      vkey,
	      (unsigned int) size);
#endif
  plugin->content_size += size;
  return GNUNET_OK;
}


/**
 * Select a subset of the items in the datastore and call
 * the given iterator for each of them.
 *
 * @param cls our "struct Plugin*"
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 */
static void
mysql_plugin_iter_low_priority (void *cls,
				enum GNUNET_BLOCK_Type type,
				PluginIterator iter,
				void *iter_cls)
{
  struct Plugin *plugin = cls;
  iterateHelper (plugin, type, GNUNET_YES, 
		 0, iter, iter_cls); 
}


struct GetContext
{
  GNUNET_HashCode key;
  GNUNET_HashCode vhash;

  unsigned int prio;
  unsigned int anonymity;
  unsigned long long expiration;
  unsigned long long vkey;
  unsigned long long total;
  int off;
  int count;
  int have_vhash;
};


static int
get_statement_prepare (void *cls,
		       struct NextRequestClosure *nrc)
{
  struct GetContext *gc = cls;
  struct Plugin *plugin;
  int ret;
  unsigned int limit_off;
  unsigned long hashSize;

  if (NULL == nrc)
    {
      GNUNET_free (gc);
      return GNUNET_NO;
    }
  if (gc->count == gc->total)
    return GNUNET_NO;
  plugin = nrc->plugin;
  hashSize = sizeof (GNUNET_HashCode);
  if (gc->count + gc->off == gc->total)
    nrc->last_vkey = 0;          /* back to start */
  if (gc->count == 0)
    limit_off = gc->off;
  else
    limit_off = 0;
#if DEBUG_MYSQL
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Obtaining result number %d/%lld at offset %d with lvc %llu for GET `%s'\n",
	      gc->count+1,
	      gc->total,
	      limit_off,
	      nrc->last_vkey,
	      GNUNET_h2s (&gc->key));  
#endif
  if (nrc->type != 0)
    {
      if (gc->have_vhash)
	{
	  ret =
	    prepared_statement_run_select
	    (plugin,
	     plugin->select_entry_by_hash_vhash_and_type, 6, nrc->rbind, &return_ok,
	     NULL, MYSQL_TYPE_BLOB, &gc->key, hashSize, &hashSize,
	     MYSQL_TYPE_BLOB, &gc->vhash, hashSize, &hashSize,
	     MYSQL_TYPE_LONGLONG, &nrc->last_vkey, GNUNET_YES, MYSQL_TYPE_LONG,
	     &nrc->type, GNUNET_YES, MYSQL_TYPE_LONG, &limit_off, GNUNET_YES,
	     -1);
	}
      else
	{
	  ret =
	    prepared_statement_run_select
	    (plugin,
	     plugin->select_entry_by_hash_and_type, 6, nrc->rbind, &return_ok, NULL,
	     MYSQL_TYPE_BLOB, &gc->key, hashSize, &hashSize,
	     MYSQL_TYPE_LONGLONG, &nrc->last_vkey, GNUNET_YES, MYSQL_TYPE_LONG,
	     &nrc->type, GNUNET_YES, MYSQL_TYPE_LONG, &limit_off, GNUNET_YES,
	     -1);
	}
    }
  else
    {
      if (gc->have_vhash)
	{
	  ret =
	    prepared_statement_run_select
	    (plugin,
	     plugin->select_entry_by_hash_and_vhash, 6, nrc->rbind, &return_ok, NULL,
	     MYSQL_TYPE_BLOB, &gc->key, hashSize, &hashSize, MYSQL_TYPE_BLOB,
	     &gc->vhash, hashSize, &hashSize, MYSQL_TYPE_LONGLONG,
	     &nrc->last_vkey, GNUNET_YES, MYSQL_TYPE_LONG, &limit_off,
	     GNUNET_YES, -1);
	}
      else
	{
	  ret =
	    prepared_statement_run_select
	    (plugin,
	     plugin->select_entry_by_hash, 6, nrc->rbind, &return_ok, NULL,
	     MYSQL_TYPE_BLOB, &gc->key, hashSize, &hashSize,
	     MYSQL_TYPE_LONGLONG, &nrc->last_vkey, GNUNET_YES, MYSQL_TYPE_LONG,
	     &limit_off, GNUNET_YES, -1);
	}
    }
  gc->count++;
  return ret;
}


/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param cls closure
 * @param key maybe NULL (to match all entries)
 * @param vhash hash of the value, maybe NULL (to
 *        match all values that have the right key).
 *        Note that for DBlocks there is no difference
 *        betwen key and vhash, but for other blocks
 *        there may be!
 * @param type entries of which type are relevant?
 *     Use 0 for any type.
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 */
static void
mysql_plugin_get (void *cls,
		  const GNUNET_HashCode * key,
		  const GNUNET_HashCode * vhash,
		  enum GNUNET_BLOCK_Type type,
		  PluginIterator iter, void *iter_cls)
{
  struct Plugin *plugin = cls;
  unsigned int itype = type;
  int ret;
  MYSQL_BIND cbind[1];
  struct GetContext *gc;
  struct NextRequestClosure *nrc;
  long long total;
  unsigned long hashSize;

  if (iter == NULL) 
    return;
  if (key == NULL)
    {
      mysql_plugin_iter_low_priority (plugin,
				      type, 
				      iter, iter_cls);
      return;
    }
  hashSize = sizeof (GNUNET_HashCode);
  memset (cbind, 0, sizeof (cbind));
  total = -1;
  cbind[0].buffer_type = MYSQL_TYPE_LONGLONG;
  cbind[0].buffer = &total;
  cbind[0].is_unsigned = GNUNET_NO;
  if (type != 0)
    {
      if (vhash != NULL)
        {
          ret =
            prepared_statement_run_select
            (plugin,
	     plugin->count_entry_by_hash_vhash_and_type, 1, cbind, &return_ok, NULL,
             MYSQL_TYPE_BLOB, key, hashSize, &hashSize, MYSQL_TYPE_BLOB,
             vhash, hashSize, &hashSize, MYSQL_TYPE_LONG, &itype, GNUNET_YES,
             -1);
        }
      else
        {
          ret =
            prepared_statement_run_select
            (plugin,
	     plugin->count_entry_by_hash_and_type, 1, cbind, &return_ok, NULL,
             MYSQL_TYPE_BLOB, key, hashSize, &hashSize, MYSQL_TYPE_LONG,
             &itype, GNUNET_YES, -1);

        }
    }
  else
    {
      if (vhash != NULL)
        {
          ret =
            prepared_statement_run_select
            (plugin,
	     plugin->count_entry_by_hash_and_vhash, 1, cbind, &return_ok, NULL,
             MYSQL_TYPE_BLOB, key, hashSize, &hashSize, MYSQL_TYPE_BLOB,
             vhash, hashSize, &hashSize, -1);

        }
      else
        {
          ret =
            prepared_statement_run_select (plugin,
					   plugin->count_entry_by_hash,
					   1, cbind, &return_ok,
					   NULL, MYSQL_TYPE_BLOB,
					   key, hashSize,
					   &hashSize, -1);
        }
    }
  if ((ret != GNUNET_OK) || (0 >= total))
    {
      iter (iter_cls, 
	    NULL, NULL, 0, NULL, 0, 0, 0, 
	    GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }
#if DEBUG_MYSQL
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Iterating over %lld results for GET `%s'\n",
	      total,
	      GNUNET_h2s (key));
#endif
  gc = GNUNET_malloc (sizeof (struct GetContext));
  gc->key = *key;
  if (vhash != NULL)
    {
      gc->have_vhash = GNUNET_YES;
      gc->vhash = *vhash;
    }
  gc->total = total;
  gc->off = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, total);
  

  nrc = GNUNET_malloc (sizeof (struct NextRequestClosure));
  nrc->plugin = plugin;
  nrc->type = type;  
  nrc->iter_select = -1;
  nrc->dviter = iter;
  nrc->dviter_cls = iter_cls;
  nrc->prep = &get_statement_prepare;
  nrc->prep_cls = gc;
  nrc->last_vkey = 0;
  mysql_plugin_next_request (nrc, GNUNET_NO);
}


/**
 * Update the priority for a particular key in the datastore.  If
 * the expiration time in value is different than the time found in
 * the datastore, the higher value should be kept.  For the
 * anonymity level, the lower value is to be used.  The specified
 * priority should be added to the existing priority, ignoring the
 * priority in value.
 *
 * Note that it is possible for multiple values to match this put.
 * In that case, all of the respective values are updated.
 *
 * @param cls our "struct Plugin*"
 * @param uid unique identifier of the datum
 * @param delta by how much should the priority
 *     change?  If priority + delta < 0 the
 *     priority should be set to 0 (never go
 *     negative).
 * @param expire new expiration time should be the
 *     MAX of any existing expiration time and
 *     this value
 * @param msg set to error message
 * @return GNUNET_OK on success
 */
static int
mysql_plugin_update (void *cls,
		     uint64_t uid,
		     int delta, 
		     struct GNUNET_TIME_Absolute expire,
		     char **msg)
{
  struct Plugin *plugin = cls;
  unsigned long long vkey = uid;
  unsigned long long lexpire = expire.value;
  int ret;

#if DEBUG_MYSQL
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Updating value %llu adding %d to priority and maxing exp at %llu\n",
	      vkey,
	      delta,
	      lexpire);
#endif
  ret = prepared_statement_run (plugin,
				plugin->update_entry,
				NULL,
				MYSQL_TYPE_LONG,
				&delta,
				GNUNET_NO,
				MYSQL_TYPE_LONGLONG,
				&lexpire,
				GNUNET_YES,
				MYSQL_TYPE_LONGLONG,
				&lexpire,
				GNUNET_YES,
				MYSQL_TYPE_LONGLONG,
				&vkey,
				GNUNET_YES, -1);
  if (ret != GNUNET_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  "Failed to update value %llu\n",
		  vkey);
    }
  return ret;
}


/**
 * Select a subset of the items in the datastore and call
 * the given iterator for each of them.
 *
 * @param cls our "struct Plugin*"
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 */
static void
mysql_plugin_iter_zero_anonymity (void *cls,
				     enum GNUNET_BLOCK_Type type,
				     PluginIterator iter,
				     void *iter_cls)
{
  struct Plugin *plugin = cls;
  iterateHelper (plugin, type, GNUNET_NO, 1, iter, iter_cls);
}


/**
 * Select a subset of the items in the datastore and call
 * the given iterator for each of them.
 *
 * @param cls our "struct Plugin*"
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 */
static void
mysql_plugin_iter_ascending_expiration (void *cls,
					enum GNUNET_BLOCK_Type type,
					PluginIterator iter,
					void *iter_cls)
{
  struct Plugin *plugin = cls;
  iterateHelper (plugin, type, GNUNET_YES, 2, iter, iter_cls);
}


/**
 * Select a subset of the items in the datastore and call
 * the given iterator for each of them.
 *
 * @param cls our "struct Plugin*"
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 */
static void
mysql_plugin_iter_migration_order (void *cls,
				      enum GNUNET_BLOCK_Type type,
				      PluginIterator iter,
				      void *iter_cls)
{
  struct Plugin *plugin = cls;
  iterateHelper (plugin, 0, GNUNET_NO, 3, iter, iter_cls);
}


/**
 * Select a subset of the items in the datastore and call
 * the given iterator for each of them.
 *
 * @param cls our "struct Plugin*"
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 */
static void
mysql_plugin_iter_all_now (void *cls,
			   enum GNUNET_BLOCK_Type type,
			   PluginIterator iter,
			   void *iter_cls)
{
  struct Plugin *plugin = cls;
  iterateHelper (plugin, 0, GNUNET_YES, 0, iter, iter_cls);
}


/**
 * Drop database.
 */
static void 
mysql_plugin_drop (void *cls)
{
  struct Plugin *plugin = cls;

  if ((GNUNET_OK != run_statement (plugin,
				   "DROP TABLE gn090")) ||
      (GNUNET_OK != run_statement (plugin,
				   "DROP TABLE gn072")))
    return;                     /* error */
  plugin->content_size = 0;
}


/**
 * Entry point for the plugin.
 *
 * @param cls the "struct GNUNET_DATASTORE_PluginEnvironment*"
 * @return our "struct Plugin*"
 */
void *
libgnunet_plugin_datastore_mysql_init (void *cls)
{
  struct GNUNET_DATASTORE_PluginEnvironment *env = cls;
  struct GNUNET_DATASTORE_PluginFunctions *api;
  struct Plugin *plugin;

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->env = env;
  plugin->cnffile = get_my_cnf_path (env->cfg);
  if (GNUNET_OK != iopen (plugin))
    {
      iclose (plugin);
      GNUNET_free_non_null (plugin->cnffile);
      GNUNET_free (plugin);
      return NULL;
    }
#define MRUNS(a) (GNUNET_OK != run_statement (plugin, a) )
#define PINIT(a,b) (NULL == (a = prepared_statement_create(plugin, b)))
  if (MRUNS ("CREATE TABLE IF NOT EXISTS gn090 ("
             " type INT(11) UNSIGNED NOT NULL DEFAULT 0,"
             " prio INT(11) UNSIGNED NOT NULL DEFAULT 0,"
             " anonLevel INT(11) UNSIGNED NOT NULL DEFAULT 0,"
             " expire BIGINT UNSIGNED NOT NULL DEFAULT 0,"
             " hash BINARY(64) NOT NULL DEFAULT '',"
             " vhash BINARY(64) NOT NULL DEFAULT '',"
             " vkey BIGINT UNSIGNED NOT NULL DEFAULT 0,"
             " INDEX hash (hash(64)),"
             " INDEX hash_vhash_vkey (hash(64),vhash(64),vkey),"
             " INDEX hash_vkey (hash(64),vkey),"
             " INDEX vkey (vkey),"
             " INDEX prio (prio,vkey),"
             " INDEX expire (expire,vkey,type),"
             " INDEX anonLevel (anonLevel,prio,vkey,type)"
             ") ENGINE=InnoDB") ||
      MRUNS ("CREATE TABLE IF NOT EXISTS gn072 ("
             " vkey BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,"
             " value BLOB NOT NULL DEFAULT '') ENGINE=MyISAM") ||
      MRUNS ("SET AUTOCOMMIT = 1") ||
      PINIT (plugin->select_value, SELECT_VALUE) ||
      PINIT (plugin->delete_value, DELETE_VALUE) ||
      PINIT (plugin->insert_value, INSERT_VALUE) ||
      PINIT (plugin->insert_entry, INSERT_ENTRY) ||
      PINIT (plugin->delete_entry_by_vkey, DELETE_ENTRY_BY_VKEY) ||
      PINIT (plugin->select_entry_by_hash, SELECT_ENTRY_BY_HASH) ||
      PINIT (plugin->select_entry_by_hash_and_vhash, SELECT_ENTRY_BY_HASH_AND_VHASH)
      || PINIT (plugin->select_entry_by_hash_and_type, SELECT_ENTRY_BY_HASH_AND_TYPE)
      || PINIT (plugin->select_entry_by_hash_vhash_and_type,
                SELECT_ENTRY_BY_HASH_VHASH_AND_TYPE)
      || PINIT (plugin->count_entry_by_hash, COUNT_ENTRY_BY_HASH)
      || PINIT (plugin->count_entry_by_hash_and_vhash, COUNT_ENTRY_BY_HASH_AND_VHASH)
      || PINIT (plugin->count_entry_by_hash_and_type, COUNT_ENTRY_BY_HASH_AND_TYPE)
      || PINIT (plugin->count_entry_by_hash_vhash_and_type,
                COUNT_ENTRY_BY_HASH_VHASH_AND_TYPE)
      || PINIT (plugin->update_entry, UPDATE_ENTRY)
      || PINIT (plugin->iter[0], SELECT_IT_LOW_PRIORITY)
      || PINIT (plugin->iter[1], SELECT_IT_NON_ANONYMOUS)
      || PINIT (plugin->iter[2], SELECT_IT_EXPIRATION_TIME)
      || PINIT (plugin->iter[3], SELECT_IT_MIGRATION_ORDER))
    {
      iclose (plugin);
      GNUNET_free_non_null (plugin->cnffile);
      GNUNET_free (plugin);
      return NULL;
    }
#undef PINIT
#undef MRUNS

  api = GNUNET_malloc (sizeof (struct GNUNET_DATASTORE_PluginFunctions));
  api->cls = plugin;
  api->get_size = &mysql_plugin_get_size;
  api->put = &mysql_plugin_put;
  api->next_request = &mysql_plugin_next_request;
  api->get = &mysql_plugin_get;
  api->update = &mysql_plugin_update;
  api->iter_low_priority = &mysql_plugin_iter_low_priority;
  api->iter_zero_anonymity = &mysql_plugin_iter_zero_anonymity;
  api->iter_ascending_expiration = &mysql_plugin_iter_ascending_expiration;
  api->iter_migration_order = &mysql_plugin_iter_migration_order;
  api->iter_all_now = &mysql_plugin_iter_all_now;
  api->drop = &mysql_plugin_drop;
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                   "mysql", _("Mysql database running\n"));
  return api;
}


/**
 * Exit point from the plugin.
 * @param cls our "struct Plugin*"
 * @return always NULL
 */
void *
libgnunet_plugin_datastore_mysql_done (void *cls)
{
  struct GNUNET_DATASTORE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  iclose (plugin);
  if (plugin->next_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (plugin->env->sched,
			       plugin->next_task);
      plugin->next_task = GNUNET_SCHEDULER_NO_TASK;
      plugin->next_task_nc->prep (plugin->next_task_nc->prep_cls, NULL);
      GNUNET_free (plugin->next_task_nc);
      plugin->next_task_nc = NULL;
    }
  GNUNET_free_non_null (plugin->cnffile);
  GNUNET_free (plugin);
  GNUNET_free (api);
  mysql_library_end ();
  return NULL;
}

/* end of plugin_datastore_mysql.c */
