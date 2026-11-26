#!/usr/bin/env python3
"""CSCI262 A3 - Email system event modeler & intrusion detection system.

Usage:  python ids.py Events.txt Stats.txt Days

Components (mirrors the report sections):
  1. Initial input      -> load_events / load_stats / check_consistency
  2. Activity engine    -> generate_logs   (writes a log file)
  3. Analysis engine    -> analyse_log     (daily totals + mean/sd)
  4. Alert engine       -> alert_loop      (anomaly counter vs threshold)
"""
import sys
import math
import random
from dataclasses import dataclass
from typing import Optional

BASELINE_LOG = "BaselineLog.txt"
LIVE_LOG = "LiveLog.txt"
BASELINE_TOTALS = "BaselineDailyTotals.txt"
BASELINE_STATS = "BaselineStats.txt"


# ---------------------------------------------------------------- 1. INPUT
@dataclass
class Event:
    name: str
    kind: str                      # 'C' or 'D'
    minimum: Optional[float]       # None = no lower bound given
    maximum: Optional[float]       # None = no upper bound given
    weight: int


@dataclass
class Stat:
    name: str
    mean: float
    sd: float


def _fields(line):
    # "Logins:D:0::2:" -> ['Logins','D','0','','2']  (trailing ':' dropped)
    parts = line.strip().split(":")
    if parts and parts[-1] == "":
        parts.pop()
    return parts


def _num(text):
    return float(text) if text.strip() != "" else None


def load_events(path):
    """Events are kept in an ORDERED list (order = order in file) plus a dict
    name -> Event for quick lookup."""
    with open(path) as f:
        lines = [l for l in f.read().splitlines() if l.strip()]
    n = int(lines[0])
    events = []
    for line in lines[1:]:
        p = _fields(line)
        events.append(Event(p[0], p[1].upper(), _num(p[2]), _num(p[3]), int(p[4])))
    if len(events) != n:
        print(f"WARNING: {path} header says {n} events but {len(events)} found")
    return events


def load_stats(path):
    with open(path) as f:
        lines = [l for l in f.read().splitlines() if l.strip()]
    n = int(lines[0])
    stats = {}
    for line in lines[1:]:
        p = _fields(line)
        stats[p[0]] = Stat(p[0], float(p[1]), float(p[2]))
    if len(stats) != n:
        print(f"WARNING: {path} header says {n} stats but {len(stats)} found")
    return stats


def check_consistency(events, stats):
    """Return a list of problems between Events.txt and Stats.txt."""
    problems = []
    ev_names = [e.name for e in events]
    for name in ev_names:
        if name not in stats:
            problems.append(f"'{name}' is in Events but missing from Stats")
    for name in stats:
        if name not in ev_names:
            problems.append(f"'{name}' is in Stats but missing from Events")
    if len(set(ev_names)) != len(ev_names):
        problems.append("duplicate event names in Events")
    for e in events:
        if e.kind not in ("C", "D"):
            problems.append(f"{e.name}: type must be C or D, got '{e.kind}'")
        if e.weight <= 0:
            problems.append(f"{e.name}: weight must be a positive integer")
        if e.minimum is not None and e.maximum is not None and e.minimum > e.maximum:
            problems.append(f"{e.name}: minimum > maximum")
        if e.kind == "D":
            for label, v in (("minimum", e.minimum), ("maximum", e.maximum)):
                if v is not None and v != int(v):
                    problems.append(f"{e.name}: discrete event has non-integer {label}")
        s = stats.get(e.name)
        if s is None:
            continue
        if s.sd < 0:
            problems.append(f"{e.name}: negative standard deviation")
        if e.minimum is not None and s.mean < e.minimum:
            problems.append(f"{e.name}: mean {s.mean} below minimum {e.minimum}")
        if e.maximum is not None and s.mean > e.maximum:
            problems.append(f"{e.name}: mean {s.mean} above maximum {e.maximum}")
        # Soft check: if +/-3 sd is mostly outside the range, clamping will
        # distort the distribution a lot.
        if e.minimum is not None and e.maximum is not None and s.sd > 0:
            if (e.maximum - e.minimum) < 2 * s.sd:
                problems.append(f"{e.name}: range is narrower than 2 sd, "
                                f"generated data cannot follow the distribution")
    return problems


def report_input(events, stats):
    print("\n=== Events read ===")
    print(f"{'Name':<16}{'Type':<6}{'Min':<8}{'Max':<8}{'Weight'}")
    for e in events:
        print(f"{e.name:<16}{e.kind:<6}{str(e.minimum if e.minimum is not None else '-'):<8}"
              f"{str(e.maximum if e.maximum is not None else '-'):<8}{e.weight}")
    print("\n=== Statistics read ===")
    print(f"{'Name':<16}{'Mean':<10}{'SD'}")
    for s in stats.values():
        print(f"{s.name:<16}{s.mean:<10}{s.sd}")


# ------------------------------------------------------- 2. ACTIVITY ENGINE
def draw_daily_total(e, s):
    """Draw ONE day's total for an event from Normal(mean, sd), then make it
    legal: integer for discrete, 2 d.p. for continuous, inside [min,max].
    We re-draw (rejection sampling) if out of range, which keeps the shape of
    the distribution better than clamping; clamp only as a last resort."""
    for _ in range(100):
        x = random.gauss(s.mean, s.sd)
        x = round(x) if e.kind == "D" else round(x, 2)
        if (e.minimum is None or x >= e.minimum) and (e.maximum is None or x <= e.maximum):
            return x
    x = min(max(s.mean, e.minimum if e.minimum is not None else s.mean),
            e.maximum if e.maximum is not None else s.mean)
    return int(round(x)) if e.kind == "D" else round(x, 2)


def split_continuous(total):
    """Split a continuous daily total into 1-4 occurrences (e.g. sessions)
    that sum to the total, each recorded to 2 d.p."""
    k = random.randint(1, 4)
    if total <= 0 or k == 1:
        return [round(total, 2)]
    cuts = sorted(random.uniform(0, total) for _ in range(k - 1))
    pts = [0] + cuts + [total]
    parts = [round(pts[i + 1] - pts[i], 2) for i in range(k)]
    parts[-1] = round(total - sum(parts[:-1]), 2)   # fix rounding drift
    return parts


def random_time():
    sec = random.randint(0, 86399)
    return f"{sec // 3600:02d}:{sec % 3600 // 60:02d}:{sec % 60:02d}"


def generate_logs(events, stats, days, path):
    """Log format (one occurrence per line, human readable, CSV-like):
         day,HH:MM:SS,event name,value
       e.g.  3,14:02:55,Emails sent,1
    Lines are sorted by time within each day."""
    print(f"\nActivity engine: generating {days} day(s) of events -> {path}")
    with open(path, "w") as f:
        for day in range(1, days + 1):
            lines = []
            for e in events:
                total = draw_daily_total(e, stats[e.name])
                if e.kind == "D":
                    values = [1] * int(total)           # one at a time
                else:
                    values = split_continuous(total)
                for v in values:
                    lines.append((random_time(), e.name, e.kind, v))
            lines.sort()
            for t, name, kind, v in lines:
                if kind == "C":
                    value_text = f"{v:.2f}"
                else:
                    value_text = str(int(v))
                f.write(f"{day},{t},{name},{value_text}\n")
            if days <= 20 or day % max(1, days // 10) == 0 or day == days:
                print(f"  day {day}/{days} done ({len(lines)} events)")
    print("Activity engine: event generation complete.")


# --------------------------------------------------------- 3. ANALYSIS ENGINE
def analyse_log(events, log_path, days, totals_path=None, stats_path=None):
    """Read the log, build daily totals per event (0 if nothing logged),
    and compute mean/sd. Reads whatever is in the file, so it works even if
    the data does not match the requested distribution."""
    print(f"\nAnalysis engine: reading {log_path}")
    totals = {e.name: [0.0] * days for e in events}
    with open(log_path) as f:
        for line in f:
            if not line.strip():
                continue
            day, _, name, val = line.rstrip("\n").split(",")
            day = int(day)
            if name in totals and 1 <= day <= days:
                totals[name][day - 1] += float(val)
    kind = {e.name: e.kind for e in events}
    for name in totals:
        totals[name] = [int(round(v)) if kind[name] == "D" else round(v, 2)
                        for v in totals[name]]

    if totals_path:
        with open(totals_path, "w") as f:
            f.write("Day," + ",".join(e.name for e in events) + "\n")
            for d in range(days):
                f.write(f"{d + 1}," + ",".join(str(totals[e.name][d]) for e in events) + "\n")
        print(f"Analysis engine: daily totals saved to {totals_path}")

    derived = {}
    for e in events:
        v = totals[e.name]
        mean = sum(v) / len(v)
        sd = math.sqrt(sum((x - mean) ** 2 for x in v) / len(v))  # population sd
        derived[e.name] = Stat(e.name, round(mean, 2), round(sd, 2))

    if stats_path:
        with open(stats_path, "w") as f:
            f.write(f"{len(events)}\n")
            for e in events:
                s = derived[e.name]
                f.write(f"{s.name}:{s.mean}:{s.sd}:\n")
        print(f"Analysis engine: baseline statistics saved to {stats_path}")
        print(f"{'Event':<16}{'Mean':<10}{'SD'}")
        for s in derived.values():
            print(f"{s.name:<16}{s.mean:<10}{s.sd}")
    return totals, derived


# ------------------------------------------------------------- 4. ALERT ENGINE
SD_FLOOR = 0.01   # avoid divide-by-zero if a baseline sd is 0


def alert_loop(events, baseline):
    threshold = 2 * sum(e.weight for e in events)
    while True:
        print("\n--- Alert engine ---")
        path = input("New statistics file (or 'q' to quit): ").strip()
        if path.lower() in ("q", "quit"):
            print("Goodbye.")
            return
        try:
            new_stats = load_stats(path)
        except (OSError, ValueError, IndexError) as err:
            print(f"Could not read '{path}': {err}")
            continue
        problems = check_consistency(events, new_stats)
        if problems:
            print("Problems with that file:")
            for p in problems:
                print("  -", p)
            continue
        try:
            days = int(input("Number of days to simulate: "))
            if days < 1:
                raise ValueError
        except ValueError:
            print("Please enter a positive whole number.")
            continue

        generate_logs(events, new_stats, days, LIVE_LOG)
        totals, _ = analyse_log(events, LIVE_LOG, days)

        print(f"\nThreshold = 2 x sum(weights) = {threshold}")
        for d in range(days):
            counter = 0.0
            for e in events:
                b = baseline[e.name]
                dev = abs(totals[e.name][d] - b.mean) / max(b.sd, SD_FLOOR)
                counter += dev * e.weight
            status = "FLAGGED" if counter >= threshold else "okay"
            print(f"Day {d + 1:>3}: threshold={threshold}  anomaly counter={counter:7.2f}  -> {status}")


# ------------------------------------------------------------------------ main
def main():
    if len(sys.argv) != 4:
        print("Usage: python ids.py Events.txt Stats.txt Days")
        sys.exit(1)
    try:
        days = int(sys.argv[3])
        if days < 1:
            raise ValueError
        events = load_events(sys.argv[1])
        stats = load_stats(sys.argv[2])
    except (OSError, ValueError, IndexError) as err:
        print(f"Input error: {err}")
        sys.exit(1)

    report_input(events, stats)
    problems = check_consistency(events, stats)
    if problems:
        print("\nInconsistencies found:")
        for p in problems:
            print("  -", p)
        sys.exit(1)
    print("\nEvents.txt and Stats.txt are consistent.")

    generate_logs(events, stats, days, BASELINE_LOG)
    print("\nStarting analysis phase...")
    _, baseline = analyse_log(events, BASELINE_LOG, days, BASELINE_TOTALS, BASELINE_STATS)
    alert_loop(events, baseline)


if __name__ == "__main__":
    main()
