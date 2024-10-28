/*
     This file is part of GNUnet.
     Copyright (C) 2001-2013, 2018 GNUnet e.V.

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
 * @file util/time.c
 * @author Christian Grothoff
 * @brief functions for handling time and time arithmetic
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#if __STDC_NO_ATOMICS__
#define ATOMIC
#else
#ifdef HAVE_STDATOMIC_H
#include <stdatomic.h>
#define ATOMIC _Atomic
#else
#define __STDC_NO_ATOMICS__ 1
#define ATOMIC
#endif
#endif

#define LOG(kind, ...) GNUNET_log_from (kind, "util-time", __VA_ARGS__)

/**
 * Variable used to simulate clock skew.  Used for testing, never in production.
 */
static long long timestamp_offset;

void
GNUNET_TIME_set_offset (long long offset)
{
  timestamp_offset = offset;
}


long long
GNUNET_TIME_get_offset ()
{
  return timestamp_offset;
}


bool
GNUNET_TIME_absolute_approx_eq (struct GNUNET_TIME_Absolute a1,
                                struct GNUNET_TIME_Absolute a2,
                                struct GNUNET_TIME_Relative t)
{
  struct GNUNET_TIME_Relative delta;

  delta = GNUNET_TIME_relative_min (
    GNUNET_TIME_absolute_get_difference (a1, a2),
    GNUNET_TIME_absolute_get_difference (a2, a1));
  return GNUNET_TIME_relative_cmp (delta,
                                   <=,
                                   t);
}


struct GNUNET_TIME_Timestamp
GNUNET_TIME_absolute_to_timestamp (struct GNUNET_TIME_Absolute at)
{
  struct GNUNET_TIME_Timestamp ts;

  if (GNUNET_TIME_absolute_is_never (at))
    return GNUNET_TIME_UNIT_FOREVER_TS;
  ts.abs_time.abs_value_us = at.abs_value_us - at.abs_value_us % 1000000;
  return ts;
}


struct GNUNET_TIME_TimestampNBO
GNUNET_TIME_timestamp_hton (struct GNUNET_TIME_Timestamp t)
{
  struct GNUNET_TIME_TimestampNBO tn;

  tn.abs_time_nbo = GNUNET_TIME_absolute_hton (t.abs_time);
  return tn;
}


struct GNUNET_TIME_Timestamp
GNUNET_TIME_timestamp_ntoh (struct GNUNET_TIME_TimestampNBO tn)
{
  struct GNUNET_TIME_Timestamp t;

  t.abs_time = GNUNET_TIME_absolute_ntoh (tn.abs_time_nbo);
  return t;
}


struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_get ()
{
  struct GNUNET_TIME_Absolute ret;
  struct timeval tv;

  gettimeofday (&tv, NULL);
  ret.abs_value_us = (uint64_t) (((uint64_t) tv.tv_sec * 1000LL * 1000LL)
                                 + ((uint64_t) tv.tv_usec))
                     + timestamp_offset;
  return ret;
}


struct GNUNET_TIME_Timestamp
GNUNET_TIME_timestamp_get ()
{
  return GNUNET_TIME_absolute_to_timestamp (
    GNUNET_TIME_absolute_get ());
}


struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_zero_ ()
{
  static struct GNUNET_TIME_Relative zero;

  return zero;
}


struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_get_zero_ ()
{
  static struct GNUNET_TIME_Absolute zero;

  return zero;
}


struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_unit_ ()
{
  static struct GNUNET_TIME_Relative one = { 1 };

  return one;
}


struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_millisecond_ ()
{
  static struct GNUNET_TIME_Relative one = { 1000 };

  return one;
}


struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_second_ ()
{
  static struct GNUNET_TIME_Relative one = { 1000 * 1000LL };

  return one;
}


struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_minute_ ()
{
  static struct GNUNET_TIME_Relative one = { 60 * 1000 * 1000LL };

  return one;
}


struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_hour_ ()
{
  static struct GNUNET_TIME_Relative one = { 60 * 60 * 1000 * 1000LL };

  return one;
}


struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_forever_ ()
{
  static struct GNUNET_TIME_Relative forever = { UINT64_MAX };

  return forever;
}


struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_get_forever_ ()
{
  static struct GNUNET_TIME_Absolute forever = { UINT64_MAX };

  return forever;
}


const char *
GNUNET_TIME_timestamp2s (struct GNUNET_TIME_Timestamp ts)
{
  static GNUNET_THREAD_LOCAL char buf[255];
  time_t tt;
  struct tm *tp;

  if (GNUNET_TIME_absolute_is_never (ts.abs_time))
    return "never";
  tt = ts.abs_time.abs_value_us / 1000LL / 1000LL;
  tp = localtime (&tt);
  /* This is hacky, but i don't know a way to detect libc character encoding.
   * Just expect utf8 from glibc these days.
   * As for msvcrt, use the wide variant, which always returns utf16
   * (otherwise we'd have to detect current codepage or use W32API character
   * set conversion routines to convert to UTF8).
   */
  strftime (buf,
            sizeof(buf),
            "%a %b %d %H:%M:%S %Y",
            tp);
  return buf;
}


const char *
GNUNET_TIME_absolute2s (struct GNUNET_TIME_Absolute t)
{
  static GNUNET_THREAD_LOCAL char buf[255];
  time_t tt;
  struct tm *tp;

  if (GNUNET_TIME_absolute_is_never (t))
    return "never";
  tt = t.abs_value_us / 1000LL / 1000LL;
  tp = localtime (&tt);
  /* This is hacky, but i don't know a way to detect libc character encoding.
   * Just expect utf8 from glibc these days.
   * As for msvcrt, use the wide variant, which always returns utf16
   * (otherwise we'd have to detect current codepage or use W32API character
   * set conversion routines to convert to UTF8).
   */
  strftime (buf,
            sizeof(buf),
            "%a %b %d %H:%M:%S %Y",
            tp);
  return buf;
}


const char *
GNUNET_TIME_relative2s (struct GNUNET_TIME_Relative delta,
                        bool do_round)
{
  static GNUNET_THREAD_LOCAL char buf[128];
  const char *unit = /* time unit */ "µs";
  uint64_t dval = delta.rel_value_us;

  if (GNUNET_TIME_relative_is_forever (delta))
    return "forever";
  if (0 == delta.rel_value_us)
    return "0 ms";
  if ( ((GNUNET_YES == do_round) &&
        (dval > 5 * 1000)) ||
       (0 == (dval % 1000)))
  {
    dval = dval / 1000;
    unit = /* time unit */ "ms";
    if (((GNUNET_YES == do_round) && (dval > 5 * 1000)) || (0 == (dval % 1000)))
    {
      dval = dval / 1000;
      unit = /* time unit */ "s";
      if (((GNUNET_YES == do_round) && (dval > 5 * 60)) || (0 == (dval % 60)))
      {
        dval = dval / 60;
        unit = /* time unit */ "m";
        if (((GNUNET_YES == do_round) && (dval > 5 * 60)) || (0 == (dval % 60)))
        {
          dval = dval / 60;
          unit = /* time unit */ "h";
          if (((GNUNET_YES == do_round) && (dval > 5 * 24)) ||
              (0 == (dval % 24)))
          {
            dval = dval / 24;
            if (1 == dval)
              unit = /* time unit */ "day";
            else
              unit = /* time unit */ "days";
          }
        }
      }
    }
  }
  GNUNET_snprintf (buf,
                   sizeof(buf),
                   "%llu %s",
                   (unsigned long long) dval,
                   unit);
  return buf;
}


struct GNUNET_TIME_Absolute
GNUNET_TIME_relative_to_absolute (struct GNUNET_TIME_Relative rel)
{
  struct GNUNET_TIME_Absolute ret;
  struct GNUNET_TIME_Absolute now;

  if (GNUNET_TIME_relative_is_forever (rel))
    return GNUNET_TIME_UNIT_FOREVER_ABS;
  now = GNUNET_TIME_absolute_get ();

  if (rel.rel_value_us + now.abs_value_us < rel.rel_value_us)
  {
    GNUNET_break (0);  /* overflow... */
    return GNUNET_TIME_UNIT_FOREVER_ABS;
  }
  ret.abs_value_us = rel.rel_value_us + now.abs_value_us;
  return ret;
}


struct GNUNET_TIME_Timestamp
GNUNET_TIME_relative_to_timestamp (struct GNUNET_TIME_Relative rel)
{
  return GNUNET_TIME_absolute_to_timestamp (
    GNUNET_TIME_relative_to_absolute (rel));
}


struct GNUNET_TIME_Relative
GNUNET_TIME_relative_min (struct GNUNET_TIME_Relative t1,
                          struct GNUNET_TIME_Relative t2)
{
  return (t1.rel_value_us < t2.rel_value_us) ? t1 : t2;
}


struct GNUNET_TIME_Relative
GNUNET_TIME_relative_max (struct GNUNET_TIME_Relative t1,
                          struct GNUNET_TIME_Relative t2)
{
  return (t1.rel_value_us > t2.rel_value_us) ? t1 : t2;
}


struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_min (struct GNUNET_TIME_Absolute t1,
                          struct GNUNET_TIME_Absolute t2)
{
  return (t1.abs_value_us < t2.abs_value_us) ? t1 : t2;
}


struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_max (struct GNUNET_TIME_Absolute t1,
                          struct GNUNET_TIME_Absolute t2)
{
  return (t1.abs_value_us > t2.abs_value_us) ? t1 : t2;
}


struct GNUNET_TIME_Timestamp
GNUNET_TIME_timestamp_max (struct GNUNET_TIME_Timestamp t1,
                           struct GNUNET_TIME_Timestamp t2)
{
  return (t1.abs_time.abs_value_us > t2.abs_time.abs_value_us) ? t1 : t2;
}


struct GNUNET_TIME_Timestamp
GNUNET_TIME_timestamp_min (struct GNUNET_TIME_Timestamp t1,
                           struct GNUNET_TIME_Timestamp t2)
{
  return (t1.abs_time.abs_value_us < t2.abs_time.abs_value_us) ? t1 : t2;
}


struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_round_down (struct GNUNET_TIME_Absolute at,
                                 struct GNUNET_TIME_Relative rt)
{
  struct GNUNET_TIME_Absolute ret;

  GNUNET_assert (! GNUNET_TIME_relative_is_zero (rt));
  ret.abs_value_us
    = at.abs_value_us
      - at.abs_value_us % rt.rel_value_us;
  return ret;
}


struct GNUNET_TIME_Relative
GNUNET_TIME_absolute_get_remaining (struct GNUNET_TIME_Absolute future)
{
  struct GNUNET_TIME_Relative ret;
  struct GNUNET_TIME_Absolute now;

  if (GNUNET_TIME_absolute_is_never (future))
    return GNUNET_TIME_UNIT_FOREVER_REL;
  now = GNUNET_TIME_absolute_get ();

  if (now.abs_value_us > future.abs_value_us)
    return GNUNET_TIME_UNIT_ZERO;
  ret.rel_value_us = future.abs_value_us - now.abs_value_us;
  return ret;
}


struct GNUNET_TIME_Relative
GNUNET_TIME_absolute_get_difference (struct GNUNET_TIME_Absolute start,
                                     struct GNUNET_TIME_Absolute end)
{
  struct GNUNET_TIME_Relative ret;

  if (GNUNET_TIME_absolute_is_never (end))
    return GNUNET_TIME_UNIT_FOREVER_REL;
  if (end.abs_value_us < start.abs_value_us)
    return GNUNET_TIME_UNIT_ZERO;
  ret.rel_value_us = end.abs_value_us - start.abs_value_us;
  return ret;
}


struct GNUNET_TIME_Relative
GNUNET_TIME_absolute_get_duration (struct GNUNET_TIME_Absolute whence)
{
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Relative ret;

  now = GNUNET_TIME_absolute_get ();
  if (whence.abs_value_us > now.abs_value_us)
    return GNUNET_TIME_UNIT_ZERO;
  ret.rel_value_us = now.abs_value_us - whence.abs_value_us;
  return ret;
}


struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_add (struct GNUNET_TIME_Absolute start,
                          struct GNUNET_TIME_Relative duration)
{
  struct GNUNET_TIME_Absolute ret;

  if (GNUNET_TIME_absolute_is_never (start) ||
      GNUNET_TIME_relative_is_forever (duration))
    return GNUNET_TIME_UNIT_FOREVER_ABS;
  if (start.abs_value_us + duration.rel_value_us < start.abs_value_us)
  {
    GNUNET_break (0);
    return GNUNET_TIME_UNIT_FOREVER_ABS;
  }
  ret.abs_value_us = start.abs_value_us + duration.rel_value_us;
  return ret;
}


struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_subtract (struct GNUNET_TIME_Absolute start,
                               struct GNUNET_TIME_Relative duration)
{
  struct GNUNET_TIME_Absolute ret;

  if (start.abs_value_us <= duration.rel_value_us)
    return GNUNET_TIME_UNIT_ZERO_ABS;
  if (GNUNET_TIME_absolute_is_never (start))
    return GNUNET_TIME_UNIT_FOREVER_ABS;
  ret.abs_value_us = start.abs_value_us - duration.rel_value_us;
  return ret;
}


struct GNUNET_TIME_Relative
GNUNET_TIME_relative_multiply (struct GNUNET_TIME_Relative rel,
                               unsigned long long factor)
{
  struct GNUNET_TIME_Relative ret;

  if (0 == factor)
    return GNUNET_TIME_UNIT_ZERO;
  if (GNUNET_TIME_relative_is_forever (rel))
    return GNUNET_TIME_UNIT_FOREVER_REL;
  ret.rel_value_us = rel.rel_value_us * factor;
  if (ret.rel_value_us / factor != rel.rel_value_us)
  {
    GNUNET_break (0);
    return GNUNET_TIME_UNIT_FOREVER_REL;
  }
  return ret;
}


struct GNUNET_TIME_Relative
GNUNET_TIME_relative_multiply_double (struct GNUNET_TIME_Relative rel,
                                      double factor)
{
  struct GNUNET_TIME_Relative out;
  double m;

  GNUNET_assert (0 <= factor);

  if (0 == factor)
    return GNUNET_TIME_UNIT_ZERO;
  if (GNUNET_TIME_relative_is_forever (rel))
    return GNUNET_TIME_UNIT_FOREVER_REL;

  m = ((double) rel.rel_value_us) * factor;

  if (m >= (double) (GNUNET_TIME_UNIT_FOREVER_REL).rel_value_us)
  {
    GNUNET_break (0);
    return GNUNET_TIME_UNIT_FOREVER_REL;
  }

  out.rel_value_us = (uint64_t) m;
  return out;
}


struct GNUNET_TIME_Relative
GNUNET_TIME_relative_saturating_multiply (struct GNUNET_TIME_Relative rel,
                                          unsigned long long factor)
{
  struct GNUNET_TIME_Relative ret;

  if (0 == factor)
    return GNUNET_TIME_UNIT_ZERO;
  if (GNUNET_TIME_relative_is_forever (rel))
    return GNUNET_TIME_UNIT_FOREVER_REL;
  ret.rel_value_us = rel.rel_value_us * factor;
  if (ret.rel_value_us / factor != rel.rel_value_us)
  {
    return GNUNET_TIME_UNIT_FOREVER_REL;
  }
  return ret;
}


struct GNUNET_TIME_Relative
GNUNET_TIME_relative_divide (struct GNUNET_TIME_Relative rel,
                             unsigned long long factor)
{
  struct GNUNET_TIME_Relative ret;

  if ((0 == factor) ||
      (GNUNET_TIME_relative_is_forever (rel)))
    return GNUNET_TIME_UNIT_FOREVER_REL;
  ret.rel_value_us = rel.rel_value_us / factor;
  return ret;
}


struct GNUNET_TIME_Relative
GNUNET_TIME_calculate_eta (struct GNUNET_TIME_Absolute start,
                           uint64_t finished,
                           uint64_t total)
{
  struct GNUNET_TIME_Relative due;
  double exp;
  struct GNUNET_TIME_Relative ret;

  GNUNET_break (finished <= total);
  if (finished >= total)
    return GNUNET_TIME_UNIT_ZERO;
  if (0 == finished)
    return GNUNET_TIME_UNIT_FOREVER_REL;
  due = GNUNET_TIME_absolute_get_duration (start);
  exp = ((double) due.rel_value_us) * ((double) total) / ((double) finished);
  ret.rel_value_us = ((uint64_t) exp) - due.rel_value_us;
  return ret;
}


struct GNUNET_TIME_Relative
GNUNET_TIME_relative_add (struct GNUNET_TIME_Relative a1,
                          struct GNUNET_TIME_Relative a2)
{
  struct GNUNET_TIME_Relative ret;

  if ((a1.rel_value_us == UINT64_MAX) || (a2.rel_value_us == UINT64_MAX))
    return GNUNET_TIME_UNIT_FOREVER_REL;
  if (a1.rel_value_us + a2.rel_value_us < a1.rel_value_us)
  {
    GNUNET_break (0);
    return GNUNET_TIME_UNIT_FOREVER_REL;
  }
  ret.rel_value_us = a1.rel_value_us + a2.rel_value_us;
  return ret;
}


struct GNUNET_TIME_Relative
GNUNET_TIME_relative_subtract (struct GNUNET_TIME_Relative a1,
                               struct GNUNET_TIME_Relative a2)
{
  struct GNUNET_TIME_Relative ret;

  if (a2.rel_value_us >= a1.rel_value_us)
    return GNUNET_TIME_UNIT_ZERO;
  if (a1.rel_value_us == UINT64_MAX)
    return GNUNET_TIME_UNIT_FOREVER_REL;
  ret.rel_value_us = a1.rel_value_us - a2.rel_value_us;
  return ret;
}


struct GNUNET_TIME_RelativeNBO
GNUNET_TIME_relative_hton (struct GNUNET_TIME_Relative a)
{
  struct GNUNET_TIME_RelativeNBO ret;

  ret.rel_value_us__ = GNUNET_htonll (a.rel_value_us);
  return ret;
}


struct GNUNET_TIME_Relative
GNUNET_TIME_relative_ntoh (struct GNUNET_TIME_RelativeNBO a)
{
  struct GNUNET_TIME_Relative ret;

  ret.rel_value_us = GNUNET_ntohll (a.rel_value_us__);
  return ret;
}


struct GNUNET_TIME_AbsoluteNBO
GNUNET_TIME_absolute_hton (struct GNUNET_TIME_Absolute a)
{
  struct GNUNET_TIME_AbsoluteNBO ret;

  ret.abs_value_us__ = GNUNET_htonll (a.abs_value_us);
  return ret;
}


bool
GNUNET_TIME_absolute_is_never (struct GNUNET_TIME_Absolute abs)
{
  return GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us == abs.abs_value_us;
}


bool
GNUNET_TIME_relative_is_forever (struct GNUNET_TIME_Relative rel)
{
  return GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us == rel.rel_value_us;
}


bool
GNUNET_TIME_relative_is_zero (struct GNUNET_TIME_Relative rel)
{
  return 0 == rel.rel_value_us;
}


bool
GNUNET_TIME_absolute_is_past (struct GNUNET_TIME_Absolute abs)
{
  struct GNUNET_TIME_Absolute now;

  now = GNUNET_TIME_absolute_get ();
  return abs.abs_value_us < now.abs_value_us;
}


bool
GNUNET_TIME_absolute_is_future (struct GNUNET_TIME_Absolute abs)
{
  struct GNUNET_TIME_Absolute now;

  now = GNUNET_TIME_absolute_get ();
  return abs.abs_value_us > now.abs_value_us;
}


struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_from_ms (uint64_t ms_after_epoch)
{
  struct GNUNET_TIME_Absolute ret;

  ret.abs_value_us = GNUNET_TIME_UNIT_MILLISECONDS.rel_value_us
                     * ms_after_epoch;
  if (ret.abs_value_us / GNUNET_TIME_UNIT_MILLISECONDS.rel_value_us !=
      ms_after_epoch)
    ret = GNUNET_TIME_UNIT_FOREVER_ABS;
  return ret;
}


struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_from_s (uint64_t s_after_epoch)
{
  struct GNUNET_TIME_Absolute ret;

  ret.abs_value_us = GNUNET_TIME_UNIT_SECONDS.rel_value_us * s_after_epoch;
  if (ret.abs_value_us / GNUNET_TIME_UNIT_SECONDS.rel_value_us !=
      s_after_epoch)
    ret = GNUNET_TIME_UNIT_FOREVER_ABS;
  return ret;
}


struct GNUNET_TIME_Timestamp
GNUNET_TIME_timestamp_from_s (uint64_t s_after_epoch)
{
  struct GNUNET_TIME_Timestamp ret;

  ret.abs_time.abs_value_us
    = GNUNET_TIME_UNIT_SECONDS.rel_value_us * s_after_epoch;
  if (ret.abs_time.abs_value_us / GNUNET_TIME_UNIT_SECONDS.rel_value_us
      != s_after_epoch)
    ret = GNUNET_TIME_UNIT_FOREVER_TS;
  return ret;
}


uint64_t
GNUNET_TIME_timestamp_to_s (struct GNUNET_TIME_Timestamp ts)
{
  if (GNUNET_TIME_absolute_is_never (ts.abs_time))
    return UINT64_MAX;
  return ts.abs_time.abs_value_us / GNUNET_TIME_UNIT_SECONDS.rel_value_us;
}


struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_ntoh (struct GNUNET_TIME_AbsoluteNBO a)
{
  struct GNUNET_TIME_Absolute ret;

  ret.abs_value_us = GNUNET_ntohll (a.abs_value_us__);
  return ret;
}


unsigned int
GNUNET_TIME_get_current_year ()
{
  time_t tp;
  struct tm *t;

  tp = time (NULL);
  t = gmtime (&tp);
  if (t == NULL)
    return 0;
  return t->tm_year + 1900;
}


unsigned int
GNUNET_TIME_time_to_year (struct GNUNET_TIME_Absolute at)
{
  struct tm *t;
  time_t tp;

  tp = at.abs_value_us / 1000LL / 1000LL; /* microseconds to seconds */
  t = gmtime (&tp);
  if (t == NULL)
    return 0;
  return t->tm_year + 1900;
}


#ifndef HAVE_TIMEGM
/**
 * As suggested in the timegm() man page.
 */
static time_t
my_timegm (struct tm *tm)
{
  time_t ret;
  char *tz;

  tz = getenv ("TZ");
  setenv ("TZ", "", 1);
  tzset ();
  ret = mktime (tm);
  if (tz)
    setenv ("TZ", tz, 1);
  else
    unsetenv ("TZ");
  tzset ();
  return ret;
}


#endif


struct GNUNET_TIME_Absolute
GNUNET_TIME_year_to_time (unsigned int year)
{
  struct GNUNET_TIME_Absolute ret;
  time_t tp;
  struct tm t;

  memset (&t, 0, sizeof(t));
  if (year < 1900)
  {
    GNUNET_break (0);
    return GNUNET_TIME_absolute_get ();  /* now */
  }
  t.tm_year = year - 1900;
  t.tm_mday = 1;
  t.tm_mon = 0;
  t.tm_wday = 1;
  t.tm_yday = 1;
#ifndef HAVE_TIMEGM
  tp = my_timegm (&t);
#else
  tp = timegm (&t);
#endif
  GNUNET_break (tp != (time_t) -1);
  ret.abs_value_us = tp * 1000LL * 1000LL; /* seconds to microseconds */
  return ret;
}


struct GNUNET_TIME_Relative
GNUNET_TIME_randomized_backoff (struct GNUNET_TIME_Relative rt,
                                struct GNUNET_TIME_Relative threshold)
{
  double r = (rand () % 500) / 1000.0;
  struct GNUNET_TIME_Relative t;

  t = GNUNET_TIME_relative_multiply_double (
    GNUNET_TIME_relative_max (GNUNET_TIME_UNIT_MILLISECONDS, rt),
    2 + r);
  return GNUNET_TIME_relative_min (threshold, t);
}


bool
GNUNET_TIME_absolute_is_zero (struct GNUNET_TIME_Absolute abs)
{
  return 0 == abs.abs_value_us;
}


struct GNUNET_TIME_Relative
GNUNET_TIME_randomize (struct GNUNET_TIME_Relative r)
{
  double d = ((rand () % 1001) + 500) / 1000.0;

  return GNUNET_TIME_relative_multiply_double (r, d);
}


struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_get_monotonic (
  const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static const struct GNUNET_CONFIGURATION_Handle *last_cfg;
  static struct GNUNET_TIME_Absolute last_time;
  static struct GNUNET_DISK_MapHandle *map_handle;
  static ATOMIC volatile uint64_t *map;
  struct GNUNET_TIME_Absolute now;

  now = GNUNET_TIME_absolute_get ();
  if (last_cfg != cfg)
  {
    char *filename;

    if (NULL != map_handle)
    {
      GNUNET_DISK_file_unmap (map_handle);
      map_handle = NULL;
    }
    map = NULL;

    last_cfg = cfg;
    if ((NULL != cfg) &&
        (GNUNET_OK ==
         GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                  "util",
                                                  "MONOTONIC_TIME_FILENAME",
                                                  &filename)))
    {
      struct GNUNET_DISK_FileHandle *fh;

      fh = GNUNET_DISK_file_open (filename,
                                  GNUNET_DISK_OPEN_READWRITE
                                  | GNUNET_DISK_OPEN_CREATE,
                                  GNUNET_DISK_PERM_USER_WRITE
                                  | GNUNET_DISK_PERM_GROUP_WRITE
                                  | GNUNET_DISK_PERM_USER_READ
                                  | GNUNET_DISK_PERM_GROUP_READ);
      if (NULL == fh)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _ ("Failed to map `%s', cannot assure monotonic time!\n"),
                    filename);
      }
      else
      {
        off_t size;

        size = 0;
        GNUNET_break (GNUNET_OK == GNUNET_DISK_file_handle_size (fh, &size));
        if (size < (off_t) sizeof(*map))
        {
          struct GNUNET_TIME_AbsoluteNBO o;

          o = GNUNET_TIME_absolute_hton (now);
          if (sizeof(o) != GNUNET_DISK_file_write (fh, &o, sizeof(o)))
            size = 0;
          else
            size = sizeof(o);
        }
        if (size == sizeof(*map))
        {
          map = GNUNET_DISK_file_map (fh,
                                      &map_handle,
                                      GNUNET_DISK_MAP_TYPE_READWRITE,
                                      sizeof(*map));
          if (NULL == map)
            GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                        _ (
                          "Failed to map `%s', cannot assure monotonic time!\n")
                        ,
                        filename);
        }
        else
        {
          GNUNET_log (
            GNUNET_ERROR_TYPE_WARNING,
            _ (
              "Failed to setup monotonic time file `%s', cannot assure monotonic time!\n"),
            filename);
        }
      }
      GNUNET_DISK_file_close (fh);
      GNUNET_free (filename);
    }
  }
  if (NULL != map)
  {
    struct GNUNET_TIME_AbsoluteNBO mt;

#if __STDC_NO_ATOMICS__
#if __GNUC__
    mt.abs_value_us__ = __sync_fetch_and_or (map, 0);
#else
    mt.abs_value_us__ = *map;   /* godspeed, pray this is atomic */
#endif
#else
    mt.abs_value_us__ = atomic_load (map);
#endif
    last_time =
      GNUNET_TIME_absolute_max (GNUNET_TIME_absolute_ntoh (mt), last_time);
  }
  if (now.abs_value_us <= last_time.abs_value_us)
    now.abs_value_us = last_time.abs_value_us + 1;
  last_time = now;
  if (NULL != map)
  {
    uint64_t val = GNUNET_TIME_absolute_hton (now).abs_value_us__;
#if __STDC_NO_ATOMICS__
#if __GNUC__
    (void) __sync_lock_test_and_set (map, val);
#else
    *map = val;   /* godspeed, pray this is atomic */
#endif
#else
    atomic_store (map, val);
#endif
  }
  return now;
}


void
GNUNET_util_time_fini (void);

/**
 * Destructor
 */
void __attribute__ ((destructor))
GNUNET_util_time_fini (void)
{
  (void) GNUNET_TIME_absolute_get_monotonic (NULL);
}


/* end of time.c */
