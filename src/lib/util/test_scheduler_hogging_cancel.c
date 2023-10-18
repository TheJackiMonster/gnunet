#include "gnunet_util_lib.h"
#include <unistd.h>

static int count = 0;
static int final_count;
static struct GNUNET_SCHEDULER_Task *t4;

static void end (void *cls)
{
  final_count = count;
  count = 5000;
  GNUNET_SCHEDULER_shutdown ();
}

static void self_rescheduling (void *cls)
{
  if (0 == count)
  {
    GNUNET_SCHEDULER_cancel (t4);
    GNUNET_SCHEDULER_add_delayed_with_priority (GNUNET_TIME_UNIT_MILLISECONDS,
                                                GNUNET_SCHEDULER_PRIORITY_URGENT,
                                                &end,
                                                NULL);
    sleep (1);
    /* end should be added to ready queue on next scheduler pass for certain
       now */
  }
  if (++count < 5000)
    {
      GNUNET_SCHEDULER_add_now (&self_rescheduling, NULL);
    }
}

static void to_be_canceled (void *cls)
{
  /* Don't run me! */
}


static void init (void *cls)
{
  GNUNET_SCHEDULER_add_now (&self_rescheduling, NULL);
  t4 = GNUNET_SCHEDULER_add_now (&to_be_canceled, NULL);
}


int main (int argc, char **argv)
{
  GNUNET_SCHEDULER_run (&init, NULL);
  return final_count < 5000 ? 0 : 1;
}
