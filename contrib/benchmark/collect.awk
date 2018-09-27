# This file is part of GNUnet
# Copyright (C) 2018 GNUnet e.V.
#
# GNUnet is free software: you can redistribute it and/or modify it
# under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# GNUnet is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


# Aggregate benchmarking data from multiple threads/processes
# generated by util/benchmark.c.
#
# Can be used as
# awk -f collect.awk gnunet-benchmark-{ops,urls}-*.txt


# records are of the following forms:
# op <op> count <count> time_us <time_us>
# url <url> status <status> count <count> time_us <time_us> time_us_max <time_us_max>


function abs(v) {
  return v < 0 ? -v : v
}

{
  if ($1 == "op") {
    n = $4;
    t = $6;
    op[$2]["count"] += n;
    op[$2]["time_us"] += t;
    if (n > 0) {
      op[$2]["time_us_sq"] += n * (t/n) * (t/n);
    }
    total_ops += t;
  } else if ($1 == "url") {
    n = $6;
    t = $8;
    url[$2][$4]["count"] += n;
    url[$2][$4]["time_us"] += t;
    if (n > 0) {
      url[$2][$4]["time_us_sq"] += n * (t/n) * (t/n);
    }
    max = url[$2][$4]["time_us_max"];
    url[$2][$4]["time_us_max"] = (t/n > max ? t/n : max)
  } else if ($1 == "op_baseline") {
    # take average time for operations from baseline values with format:
    # op_baseline <opname> time_avg_us <t>
    op_baseline[$2] = $4;
    have_baseline = 1;
  }
}

function avg(sum, n) {
  if (n == 0) {
    return 0;
  } else {
    return sum / n;
  }
}

function stdev(sum, sum_sq, n) {
  if (n == 0) {
    return 0;
  } else {
    return sqrt(abs((sum_sq / n) - ((sum / n) * (sum / n))));
  }
}

END {
  for (x in op) {
    print "op", x, "count", op[x]["count"], "time_us", op[x]["time_us"], \
          "time_avg_us", avg(op[x]["time_us"], op[x]["count"]), \
          "stdev", stdev(op[x]["time_us"], op[x]["time_us_sq"], op[x]["count"]);
  }
  for (x in url) {
    for (y in url[x]) {
      print "url", x, "status", y, \
            "count", url[x][y]["count"], "time_us", url[x][y]["time_us"], \
            "time_avg_us", avg(url[x][y]["time_us"], url[x][y]["count"]), \
            "stdev", stdev(url[x][y]["time_us"], url[x][y]["time_us_sq"], url[x][y]["count"]), \
            "time_us_max", url[x][y]["time_us_max"];
    }
  }
  if (total_ops) {
    print "total_ops_ms", total_ops;
  }

  # Invoke awk with -V baseline_out=<filename> to extract baseline average
  if (baseline_out) {
    for (x in op) {
      print "op_baseline", x, "time_avg_us", avg(op[x]["time_us"], op[x]["count"]) > baseline_out
    }
  }

  if (have_baseline) {
    for (x in op) {
      total_ops_adjusted[x] = op_baseline[x] * op[x]["count"];
    }
    for (x in op) {
      print "total_ops_adjusted_ms", total_ops_adjusted[x];
    }
  }
}
