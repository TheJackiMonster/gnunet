#include "gnunet_util_lib.h"
#include <unistd.h>

static int count = 0;
static int final_count;

static void end (void *cls)
{
  final_count = count;
  count = 5000;
  GNUNET_SCHEDULER_shutdown ();
}

static void self_rescheduling (void *cls)
{
  if (count == 0)
  {
    GNUNET_SCHEDULER_add_delayed_with_priority (GNUNET_TIME_UNIT_MILLISECONDS,
                                                GNUNET_SCHEDULER_PRIORITY_URGENT,
                                                &end,
                                                NULL);
    sleep(1);
    /* end should be added to ready queue on next scheduler pass for certain
       now */
  }
  if (++count < 5000)
  {
    GNUNET_SCHEDULER_add_now (&self_rescheduling, NULL);
  }
}


static void noop (void *cls)
{
}

static void indirection (void *cls)
{
  GNUNET_SCHEDULER_add_with_reason_and_priority (&self_rescheduling, NULL,
                                                 GNUNET_SCHEDULER_REASON_STARTUP,
                                                 GNUNET_SCHEDULER_PRIORITY_HIGH);
}

static void init (void *cls)
{
  GNUNET_SCHEDULER_add_now (&indirection, NULL);
  GNUNET_SCHEDULER_add_now (&noop, NULL);
}


int main (int argc, char **argv)
{
  GNUNET_SCHEDULER_run (&init, NULL);
  return final_count < 5000 ? 0 : 1;
}
