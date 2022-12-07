/*
     This file is part of GNUnet.
     Copyright (C) 2001-2022 GNUnet e.V.

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
 * @addtogroup libgnunetutil
 * Multi-function utilities library for GNUnet programs
 * @{
 *
 * @author Christian Grothoff
 *
 * @file
 * Functions related to time
 *
 * @defgroup time  Time library
 * Time and time calculations.
 * @{
 */

#ifndef GNUNET_TIME_LIB_H
#define GNUNET_TIME_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


#include "gnunet_common.h"

/**
 * Time for absolute times used by GNUnet, in microseconds.
 */
struct GNUNET_TIME_Absolute
{
  /**
   * The actual value.
   */
  uint64_t abs_value_us;
};

/**
 * Rounded time for timestamps used by GNUnet, in seconds.
 */
struct GNUNET_TIME_Timestamp
{
  /**
   * The actual value. Must be round number in seconds.
   */
  struct GNUNET_TIME_Absolute abs_time;
};

/**
 * Time for relative time used by GNUnet, in microseconds.
 * Always positive, so we can only refer to future time.
 */
struct GNUNET_TIME_Relative
{
  /**
   * The actual value.
   */
  uint64_t rel_value_us;
};

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Time for relative time used by GNUnet, in microseconds and in network byte order.
 */
struct GNUNET_TIME_RelativeNBO
{
  /**
   * The actual value (in network byte order).
   */
  uint64_t rel_value_us__ GNUNET_PACKED;
};


/**
 * Time for absolute time used by GNUnet, in microseconds and in network byte order.
 */
struct GNUNET_TIME_AbsoluteNBO
{
  /**
   * The actual value (in network byte order).
   */
  uint64_t abs_value_us__ GNUNET_PACKED;
};

/**
 * Time for timestamps used by GNUnet, in seconds and in network byte order.
 */
struct GNUNET_TIME_TimestampNBO
{
  /**
   * The actual value. Must be round number in seconds.
   */
  struct GNUNET_TIME_AbsoluteNBO abs_time_nbo;
};

GNUNET_NETWORK_STRUCT_END

/**
 * Relative time zero.
 */
#define GNUNET_TIME_UNIT_ZERO ((struct GNUNET_TIME_Relative){0})

/**
 * Absolute time zero.
 */
#define GNUNET_TIME_UNIT_ZERO_ABS ((struct GNUNET_TIME_Absolute){0})

/**
 * Timestamp of zero.
 */
#define GNUNET_TIME_UNIT_ZERO_TS ((struct GNUNET_TIME_Timestamp){{0}})

/**
 * One microsecond, our basic time unit.
 */
#define GNUNET_TIME_UNIT_MICROSECONDS GNUNET_TIME_relative_get_unit_ ()

/**
 * One millisecond.
 */
#define GNUNET_TIME_UNIT_MILLISECONDS GNUNET_TIME_relative_get_millisecond_ ()

/**
 * One second.
 */
#define GNUNET_TIME_UNIT_SECONDS GNUNET_TIME_relative_get_second_ ()

/**
 * One minute.
 */
#define GNUNET_TIME_UNIT_MINUTES GNUNET_TIME_relative_get_minute_ ()

/**
 * One hour.
 */
#define GNUNET_TIME_UNIT_HOURS   GNUNET_TIME_relative_get_hour_ ()

/**
 * One day.
 */
#define GNUNET_TIME_UNIT_DAYS    GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_HOURS, 24)

/**
 * One week.
 */
#define GNUNET_TIME_UNIT_WEEKS   GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_DAYS, 7)

/**
 * One month (30 days).
 */
#define GNUNET_TIME_UNIT_MONTHS  GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_DAYS, 30)

/**
 * One year (365 days).
 */
#define GNUNET_TIME_UNIT_YEARS   GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_DAYS, 365)

/**
 * Constant used to specify "forever".  This constant
 * will be treated specially in all time operations.
 */
#define GNUNET_TIME_UNIT_FOREVER_REL \
  ((struct GNUNET_TIME_Relative){UINT64_MAX})

/**
 * Constant used to specify "forever".  This constant
 * will be treated specially in all time operations.
 */
#define GNUNET_TIME_UNIT_FOREVER_ABS \
  ((struct GNUNET_TIME_Absolute){UINT64_MAX})

/**
 * Constant used to specify "forever".  This constant
 * will be treated specially in all time operations.
 */
#define GNUNET_TIME_UNIT_FOREVER_TS \
  ((struct GNUNET_TIME_Timestamp){{UINT64_MAX}})


/**
 * Threshold after which exponential backoff should not increase (15 m).
 */
#define GNUNET_TIME_STD_EXPONENTIAL_BACKOFF_THRESHOLD \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 15)


/**
 * Perform our standard exponential back-off calculation, starting at 1 ms
 * and then going by a factor of 2 up unto a maximum of 15 m.
 *
 * @param r current backoff time, initially zero
 */
#define GNUNET_TIME_STD_BACKOFF(r) GNUNET_TIME_relative_min ( \
    GNUNET_TIME_STD_EXPONENTIAL_BACKOFF_THRESHOLD, \
    GNUNET_TIME_relative_multiply ( \
      GNUNET_TIME_relative_max (GNUNET_TIME_UNIT_MILLISECONDS, (r)), 2))


/**
 * Convert @a ts to human-readable timestamp.
 * Note that the returned value will be overwritten if this function
 * is called again.
 *
 * @param ts the timestamp to convert
 * @return statically allocated string, will change on the next call
 */
const char *
GNUNET_TIME_timestamp2s (struct GNUNET_TIME_Timestamp ts);


/**
 * @ingroup time
 * Like `asctime`, except for GNUnet time.  Converts a GNUnet internal
 * absolute time (which is in UTC) to a string in local time.
 * Note that the returned value will be overwritten if this function
 * is called again.
 *
 * @param ts the absolute time to convert
 * @return timestamp in human-readable form in local time
 */
const char *
GNUNET_TIME_absolute2s (struct GNUNET_TIME_Absolute ts);


/**
 * @ingroup time
 * Give relative time in human-readable fancy format.
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param delta time in milli seconds
 * @param do_round are we allowed to round a bit?
 * @return string in human-readable form
 */
const char *
GNUNET_TIME_relative2s (struct GNUNET_TIME_Relative delta,
                        bool do_round);


/**
 * Randomized exponential back-off, starting at 1 ms
 * and going up by a factor of 2+r, where 0 <= r <= 0.5, up
 * to a maximum of the given threshold.
 *
 * @param rt current backoff time, initially zero
 * @param threshold maximum value for backoff
 * @return the next backoff time
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_randomized_backoff (struct GNUNET_TIME_Relative rt,
                                struct GNUNET_TIME_Relative threshold);


/**
 * Return a random time value between 0.5*r and 1.5*r.
 *
 * @param r input time for scaling
 * @return randomized time
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_randomize (struct GNUNET_TIME_Relative r);


/**
 * Return relative time of 0ms.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_zero_ (void);


/**
 * Return absolute time of 0ms.
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_get_zero_ (void);


/**
 * Return relative time of 1 microsecond.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_unit_ (void);


/**
 * Return relative time of 1ms.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_millisecond_ (void);


/**
 * Return relative time of 1s.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_second_ (void);


/**
 * Return relative time of 1 minute.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_minute_ (void);


/**
 * Return relative time of 1 hour.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_hour_ (void);


/**
 * Return "forever".
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_get_forever_ (void);


/**
 * Return "forever".
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_get_forever_ (void);


/**
 * Get the current time.
 *
 * @return the current time
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_get (void);


/**
 * Convert relative time to an absolute time in the
 * future.
 *
 * @param rel relative time to convert
 * @return timestamp that is "rel" in the future, or FOREVER if rel==FOREVER (or if we would overflow)
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_relative_to_absolute (struct GNUNET_TIME_Relative rel);


/**
 * Convert relative time to a timestamp in the
 * future.
 *
 * @param rel relative time to convert
 * @return timestamp that is "rel" in the future, or FOREVER if rel==FOREVER (or if we would overflow)
 */
struct GNUNET_TIME_Timestamp
GNUNET_TIME_relative_to_timestamp (struct GNUNET_TIME_Relative rel);


/**
 * Round an absolute time to a timestamp.
 *
 * @param at time to round
 * @return the result
 */
struct GNUNET_TIME_Timestamp
GNUNET_TIME_absolute_to_timestamp (struct GNUNET_TIME_Absolute at);


/**
 * Get timestamp representing the current time.
 *
 * @return current time, rounded down to seconds
 */
struct GNUNET_TIME_Timestamp
GNUNET_TIME_timestamp_get (void);


/**
 * Compare two absolute times.
 *
 * @param t1 first time
 * @param op compare operator
 * @param t2 second time
 * @return true if @a t1 @a op @a t2
 */
#define GNUNET_TIME_absolute_cmp(t1,op,t2) \
  ((void) (1 op 2), (t1).abs_value_us op (t2).abs_value_us)


/**
 * Compare two timestamps
 *
 * @param t1 first timestamp
 * @param op compare operator
 * @param t2 second timestamp
 * @return true if @a t1 @a op @a t2
 */
#define GNUNET_TIME_timestamp_cmp(t1,op,t2) \
  GNUNET_TIME_absolute_cmp ((t1).abs_time,op,(t2).abs_time)


/**
 * Compare two relative times.
 *
 * @param t1 first time
 * @param op compare operator
 * @param t2 second time
 * @return true if @a t1 @a op @a t2
 */
#define GNUNET_TIME_relative_cmp(t1,op,t2) \
  ((void) (1 op 2), (t1).rel_value_us op (t2).rel_value_us)


/**
 * Return the minimum of two relative time values.
 *
 * @param t1 first timestamp
 * @param t2 other timestamp
 * @return timestamp that is smaller
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_min (struct GNUNET_TIME_Relative t1,
                          struct GNUNET_TIME_Relative t2);


/**
 * Return the maximum of two relative time values.
 *
 * @param t1 first timestamp
 * @param t2 other timestamp
 * @return timestamp that is larger
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_max (struct GNUNET_TIME_Relative t1,
                          struct GNUNET_TIME_Relative t2);


/**
 * Return the minimum of two absolute time values.
 *
 * @param t1 first timestamp
 * @param t2 other timestamp
 * @return timestamp that is smaller
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_min (struct GNUNET_TIME_Absolute t1,
                          struct GNUNET_TIME_Absolute t2);


/**
 * Return the maximum of two absolute time values.
 *
 * @param t1 first timestamp
 * @param t2 other timestamp
 * @return timestamp that is smaller
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_max (struct GNUNET_TIME_Absolute t1,
                          struct GNUNET_TIME_Absolute t2);


/**
 * Round down absolute time @a at to multiple of @a rt.
 *
 * @param at absolute time to round
 * @param rt multiple to round to (non-zero)
 * @return rounded time
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_round_down (struct GNUNET_TIME_Absolute at,
                                 struct GNUNET_TIME_Relative rt);


/**
 * Return the maximum of two timestamps.
 *
 * @param t1 first timestamp
 * @param t2 other timestamp
 * @return timestamp that is smaller
 */
struct GNUNET_TIME_Timestamp
GNUNET_TIME_timestamp_max (struct GNUNET_TIME_Timestamp t1,
                           struct GNUNET_TIME_Timestamp t2);


/**
 * Return the minimum of two timestamps.
 *
 * @param t1 first timestamp
 * @param t2 other timestamp
 * @return timestamp that is smaller
 */
struct GNUNET_TIME_Timestamp
GNUNET_TIME_timestamp_min (struct GNUNET_TIME_Timestamp t1,
                           struct GNUNET_TIME_Timestamp t2);


/**
 * Given a timestamp in the future, how much time
 * remains until then?
 *
 * @param future some absolute time, typically in the future
 * @return future - now, or 0 if now >= future, or FOREVER if future==FOREVER.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_absolute_get_remaining (struct GNUNET_TIME_Absolute future);


/**
 * Test if @a a1 and @a a2 are equal within a margin of
 * error of @a t.
 *
 * @param a1 time to compare
 * @param a2 time to compare
 * @param t tolerance to apply
 * @return true if "|a1-a2|<=t" holds.
 */
bool
GNUNET_TIME_absolute_approx_eq (struct GNUNET_TIME_Absolute a1,
                                struct GNUNET_TIME_Absolute a2,
                                struct GNUNET_TIME_Relative t);


/**
 * Calculate the estimate time of arrival/completion
 * for an operation.
 *
 * @param start when did the operation start?
 * @param finished how much has been done?
 * @param total how much must be done overall (same unit as for "finished")
 * @return remaining duration for the operation,
 *        assuming it continues at the same speed
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_calculate_eta (struct GNUNET_TIME_Absolute start,
                           uint64_t finished,
                           uint64_t total);


/**
 * Compute the time difference between the given start and end times.
 * Use this function instead of actual subtraction to ensure that
 * "FOREVER" and overflows are handled correctly.
 *
 * @param start some absolute time
 * @param end some absolute time (typically larger or equal to start)
 * @return 0 if start >= end; FOREVER if end==FOREVER; otherwise end - start
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_absolute_get_difference (struct GNUNET_TIME_Absolute start,
                                     struct GNUNET_TIME_Absolute end);


/**
 * Get the duration of an operation as the
 * difference of the current time and the given start time "hence".
 *
 * @param whence some absolute time, typically in the past
 * @return 0 if hence > now, otherwise now-hence.
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_absolute_get_duration (struct GNUNET_TIME_Absolute whence);


/**
 * Add a given relative duration to the
 * given start time.
 *
 * @param start some absolute time
 * @param duration some relative time to add
 * @return FOREVER if either argument is FOREVER or on overflow; start+duration otherwise
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_add (struct GNUNET_TIME_Absolute start,
                          struct GNUNET_TIME_Relative duration);


/**
 * Subtract a given relative duration from the
 * given start time.
 *
 * @param start some absolute time
 * @param duration some relative time to subtract
 * @return ZERO if start <= duration, or FOREVER if start time is FOREVER; start-duration otherwise
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_subtract (struct GNUNET_TIME_Absolute start,
                               struct GNUNET_TIME_Relative duration);


/**
 * Multiply relative time by a given factor.
 *
 * @param rel some duration
 * @param factor integer to multiply with
 * @return FOREVER if rel=FOREVER or on overflow; otherwise rel*factor
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_multiply (struct GNUNET_TIME_Relative rel,
                               unsigned long long factor);


/**
 * Saturating multiply relative time by a given factor.
 *
 * @param rel some duration
 * @param factor integer to multiply with
 * @return FOREVER if rel=FOREVER or on overflow; otherwise rel*factor
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_saturating_multiply (struct GNUNET_TIME_Relative rel,
                                          unsigned long long factor);


/**
 * Divide relative time by a given factor.
 *
 * @param rel some duration
 * @param factor integer to divide by
 * @return FOREVER if rel=FOREVER or factor==0; otherwise rel/factor
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_divide (struct GNUNET_TIME_Relative rel,
                             unsigned long long factor);


/**
 * Add relative times together.
 *
 * @param a1 some relative time
 * @param a2 some other relative time
 * @return FOREVER if either argument is FOREVER or on overflow; a1+a2 otherwise
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_add (struct GNUNET_TIME_Relative a1,
                          struct GNUNET_TIME_Relative a2);


/**
 * Subtract relative timestamp from the other.
 *
 * @param a1 first timestamp
 * @param a2 second timestamp
 * @return ZERO if a2>=a1 (including both FOREVER), FOREVER if a1 is FOREVER, a1-a2 otherwise
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_subtract (struct GNUNET_TIME_Relative a1,
                               struct GNUNET_TIME_Relative a2);


/**
 * Convert relative time to network byte order.
 *
 * @param a time to convert
 * @return converted time value
 */
struct GNUNET_TIME_RelativeNBO
GNUNET_TIME_relative_hton (struct GNUNET_TIME_Relative a);


/**
 * Convert relative time from network byte order.
 *
 * @param a time to convert
 * @return converted time value
 */
struct GNUNET_TIME_Relative
GNUNET_TIME_relative_ntoh (struct GNUNET_TIME_RelativeNBO a);


/**
 * Convert absolute time to network byte order.
 *
 * @param a time to convert
 * @return converted time value
 */
struct GNUNET_TIME_AbsoluteNBO
GNUNET_TIME_absolute_hton (struct GNUNET_TIME_Absolute a);


/**
 * Convert timestamp to network byte order.
 *
 * @param t time to convert
 * @return converted time value
 */
struct GNUNET_TIME_TimestampNBO
GNUNET_TIME_timestamp_hton (struct GNUNET_TIME_Timestamp t);


/**
 * Convert milliseconds after the UNIX epoch to absolute time.
 *
 * @param ms_after_epoch millisecond timestamp to convert
 * @return converted time value
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_from_ms (uint64_t ms_after_epoch);


/**
 * Test if @a abs is never.
 *
 * @return true if it is.
 */
bool
GNUNET_TIME_absolute_is_never (struct GNUNET_TIME_Absolute abs);


/**
 * Test if @a abs is truly in the past (excluding now).
 *
 * @return true if it is.
 */
bool
GNUNET_TIME_absolute_is_past (struct GNUNET_TIME_Absolute abs);


/**
 * Test if @a abs is truly zero.
 *
 * @return true if it is.
 */
bool
GNUNET_TIME_absolute_is_zero (struct GNUNET_TIME_Absolute abs);


/**
 * Test if @a abs is truly in the future (excluding now).
 *
 * @return true if it is.
 */
bool
GNUNET_TIME_absolute_is_future (struct GNUNET_TIME_Absolute abs);


/**
 * Test if @a rel is forever.
 *
 * @return true if it is.
 */
bool
GNUNET_TIME_relative_is_forever (struct GNUNET_TIME_Relative rel);


/**
 * Test if @a rel is zero.
 *
 * @return true if it is.
 */
bool
GNUNET_TIME_relative_is_zero (struct GNUNET_TIME_Relative rel);


/**
 * Convert seconds after the UNIX epoch to absolute time.
 *
 * @param s_after_epoch seconds after epoch to convert
 * @return converted time value
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_from_s (uint64_t s_after_epoch);


/**
 * Convert seconds after the UNIX epoch to timestamp.
 *
 * @param s_after_epoch seconds after epoch to convert
 * @return converted time value
 */
struct GNUNET_TIME_Timestamp
GNUNET_TIME_timestamp_from_s (uint64_t s_after_epoch);


/**
 * Convert timestamp to number of seconds after the UNIX epoch.
 *
 * @param ts timestamp to convert
 * @return converted time value
 */
uint64_t
GNUNET_TIME_timestamp_to_s (struct GNUNET_TIME_Timestamp ts);


/**
 * Convert absolute time from network byte order.
 *
 * @param a time to convert
 * @return converted time value
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_ntoh (struct GNUNET_TIME_AbsoluteNBO a);


/**
 * Convert timestamp from network byte order.
 *
 * @param tn time to convert
 * @return converted time value
 */
struct GNUNET_TIME_Timestamp
GNUNET_TIME_timestamp_ntoh (struct GNUNET_TIME_TimestampNBO tn);


/**
 * Set the timestamp offset for this instance.
 *
 * @param offset the offset to skew the locale time by
 */
void
GNUNET_TIME_set_offset (long long offset);


/**
 * Get the timestamp offset for this instance.
 *
 * @return the offset we currently skew the locale time by
 */
long long
GNUNET_TIME_get_offset (void);


/**
 * Return the current year (e.g. '2011').
 */
unsigned int
GNUNET_TIME_get_current_year (void);


/**
 * Convert a year to an expiration time of January 1st of that year.
 *
 * @param year a year (after 1970, please ;-)).
 * @return absolute time for January 1st of that year.
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_year_to_time (unsigned int year);


/**
 * Convert an expiration time to the respective year (rounds)
 *
 * @param at absolute time
 * @return year a year (after 1970), 0 on error
 */
unsigned int
GNUNET_TIME_time_to_year (struct GNUNET_TIME_Absolute at);


/**
 * A configuration object.
 */
struct GNUNET_CONFIGURATION_Handle;


/**
 * Obtain the current time and make sure it is monotonically
 * increasing.  Guards against systems without an RTC or
 * clocks running backwards and other nasty surprises. Does
 * not guarantee that the returned time is near the current
 * time returned by #GNUNET_TIME_absolute_get().  Two
 * subsequent calls (within a short time period) may return the
 * same value. Persists the last returned time on disk to
 * ensure that time never goes backwards. As a result, the
 * resulting value can be used to check if a message is the
 * "most recent" value and replays of older messages (from
 * the same origin) would be discarded.
 *
 * @param cfg configuration, used to determine where to
 *   store the time; user can also insist RTC is working
 *   nicely and disable the feature
 * @return monotonically increasing time
 */
struct GNUNET_TIME_Absolute
GNUNET_TIME_absolute_get_monotonic (
  const struct GNUNET_CONFIGURATION_Handle *cfg);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_TIME_LIB_H */
#endif

/** @} */ /* end of group time */

/** @} */ /* end of group addition */

/* end of gnunet_time_lib.h */
