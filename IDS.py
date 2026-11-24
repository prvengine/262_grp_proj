#!/usr/bin/env python3
"""
CSCI262 System Security – Assignment 3
Email System Event Modeler & Intrusion Detection System

Usage:
    python IDS.py Events.txt Stats.txt Days

Components:
    1. Initial Input   – Parse Events.txt and Stats.txt; consistency checks.
    2. Activity Engine – Generate baseline event logs over <Days> days.
    3. Analysis Engine – Compute daily totals, mean & std dev per event.
    4. Alert Engine    – Detect anomalies in live data vs baseline.
"""

import sys
import os
import math
import random

# ════════════════════════════════════════════════════════════════
# Data structures
# ════════════════════════════════════════════════════════════════

class Event:
    """Holds a single event's definition from Events.txt."""
    def __init__(self, name: str, kind: str,
                 minimum: float | None, maximum: float | None,
                 weight: int):
        self.name    = name     # e.g. "Logins"
        self.kind    = kind     # 'C' (continuous) or 'D' (discrete)
        self.minimum = minimum  # lower bound, or None if unspecified
        self.maximum = maximum  # upper bound, or None if unspecified
        self.weight  = weight   # positive integer

    def __repr__(self):
        lo = str(self.minimum) if self.minimum is not None else "—"
        hi = str(self.maximum) if self.maximum is not None else "—"
        return (f"Event({self.name!r}, kind={self.kind}, "
                f"range=[{lo},{hi}], weight={self.weight})")


class EventStat:
    """Holds a single event's statistical parameters from Stats.txt."""
    def __init__(self, name: str, mean: float, std_dev: float):
        self.name    = name
        self.mean    = mean
        self.std_dev = std_dev

    def __repr__(self):
        return f"EventStat({self.name!r}, μ={self.mean}, σ={self.std_dev})"


# ════════════════════════════════════════════════════════════════
# Phase 1 – Initial Input
# ════════════════════════════════════════════════════════════════

def parse_events(filename: str) -> dict[str, Event]:
    """
    Parse Events.txt.
    Format per line: Event name:[CD]:minimum:maximum:weight:
    Storage: dict mapping event name → Event object.
    """
    events: dict[str, Event] = {}
    with open(filename, 'r') as f:
        lines = [l.strip() for l in f if l.strip()]

    count = int(lines[0])
    for line in lines[1 : count + 1]:
        parts = line.split(':')
        name    = parts[0].strip()
        kind    = parts[1].strip()
        minimum = float(parts[2]) if parts[2].strip() != '' else None
        maximum = float(parts[3]) if parts[3].strip() != '' else None
        weight  = int(parts[4])
        events[name] = Event(name, kind, minimum, maximum, weight)

    return events


def parse_stats(filename: str) -> dict[str, EventStat]:
    """
    Parse Stats.txt.
    Format per line: Event name:mean:standard deviation:
    Storage: dict mapping event name → EventStat object.
    """
    stats: dict[str, EventStat] = {}
    with open(filename, 'r') as f:
        lines = [l.strip() for l in f if l.strip()]

    count = int(lines[0])
    for line in lines[1 : count + 1]:
        parts   = line.split(':')
        name    = parts[0].strip()
        mean    = float(parts[1])
        std_dev = float(parts[2])
        stats[name] = EventStat(name, mean, std_dev)

    return stats


def print_events(events: dict[str, Event]):
    print(f"\n  {'Event':<20} {'Type':<12} {'Min':>6} {'Max':>8} {'Weight':>7}")
    print(f"  {'─'*20} {'─'*12} {'─'*6} {'─'*8} {'─'*7}")
    for e in events.values():
        lo = f"{e.minimum}" if e.minimum is not None else "—"
        hi = f"{e.maximum}" if e.maximum is not None else "—"
        kind_str = "Continuous" if e.kind == 'C' else "Discrete"
        print(f"  {e.name:<20} {kind_str:<12} {lo:>6} {hi:>8} {e.weight:>7}")


def print_stats(stats: dict[str, EventStat]):
    print(f"\n  {'Event':<20} {'Mean':>10} {'Std Dev':>10}")
    print(f"  {'─'*20} {'─'*10} {'─'*10}")
    for s in stats.values():
        print(f"  {s.name:<20} {s.mean:>10.4f} {s.std_dev:>10.4f}")


def check_consistency(events: dict[str, Event],
                       stats:  dict[str, EventStat]) -> list[str]:
    """
    Detect inconsistencies between Events.txt and Stats.txt.

    Checks performed:
      1. Events present in one file but not the other.
      2. Event type count mismatch.
      3. Mean outside [minimum, maximum] range.
      4. Negative standard deviation.
      5. Discrete event with non-integer mean (informational).
      6. Standard deviation of zero (informational).
    """
    issues: list[str] = []
    event_names = set(events.keys())
    stat_names  = set(stats.keys())

    for name in event_names - stat_names:
        issues.append(f"[WARNING] '{name}' defined in Events.txt but absent from Stats.txt.")
    for name in stat_names - event_names:
        issues.append(f"[WARNING] '{name}' defined in Stats.txt but absent from Events.txt.")

    for name in event_names & stat_names:
        e, s = events[name], stats[name]

        if s.std_dev < 0:
            issues.append(f"[ERROR]   '{name}': standard deviation ({s.std_dev}) is negative.")

        if e.minimum is not None and s.mean < e.minimum:
            issues.append(
                f"[WARNING] '{name}': mean ({s.mean}) is below minimum ({e.minimum}).")
        if e.maximum is not None and s.mean > e.maximum:
            issues.append(
                f"[WARNING] '{name}': mean ({s.mean}) exceeds maximum ({e.maximum}).")

        if e.kind == 'D' and s.mean != round(s.mean):
            issues.append(
                f"[INFO]    '{name}' is discrete but mean ({s.mean}) is not an integer.")

        if s.std_dev == 0:
            issues.append(
                f"[INFO]    '{name}': standard deviation is 0 — values will be fixed at mean.")

    if len(event_names) != len(stat_names):
        issues.append(
            f"[WARNING] Event count mismatch: "
            f"Events.txt has {len(event_names)}, Stats.txt has {len(stat_names)}.")

    return issues


# ════════════════════════════════════════════════════════════════
# Phase 2 – Activity Engine
# ════════════════════════════════════════════════════════════════

LOG_FILE = "activity_log.txt"

def _sample_value(event: Event, stat: EventStat) -> int | float:
    """
    Draw one value from a Gaussian distribution N(mean, std_dev),
    clamped to [minimum, maximum].

    - Discrete (D): rounded to nearest integer, cast to int.
    - Continuous (C): rounded to 2 decimal places.
    """
    value = random.gauss(stat.mean, stat.std_dev) if stat.std_dev > 0 else stat.mean

    # Clamp to allowed range
    if event.minimum is not None:
        value = max(event.minimum, value)
    if event.maximum is not None:
        value = min(event.maximum, value)

    if event.kind == 'D':
        return int(round(value))
    else:
        return round(value, 2)


def activity_engine(events: dict[str, Event],
                     stats:  dict[str, EventStat],
                     days:   int,
                     log_file: str = LOG_FILE) -> list[dict]:
    """
    Generate and log events for <days> days.

    Log file format (human-readable, pipe-delimited):
        # comment lines
        [Day N]
        EventName | Type | Value

    Returns a list of dicts: [{event_name: value, ...}, ...]  (one per day).
    """
    print(f"\n  Generating events for {days} day(s) → '{log_file}'")

    all_days: list[dict] = []

    with open(log_file, 'w') as f:
        f.write("# Activity Log – Email IDS\n")
        f.write("# Format: EventName | Type (C/D) | Value\n")
        f.write(f"# Days: {days}\n")
        f.write("#" + "─" * 50 + "\n")

        for day in range(1, days + 1):
            day_data: dict = {}
            f.write(f"\n[Day {day}]\n")

            for name, event in events.items():
                if name not in stats:
                    continue
                value = _sample_value(event, stats[name])
                day_data[name] = value
                f.write(f"{name} | {event.kind} | {value}\n")

            all_days.append(day_data)
            print(f"    Day {day}/{days} logged.", end='\r')

    print(f"    Done — {days} day(s) logged.                ")
    return all_days


def read_log(log_file: str, events: dict[str, Event]) -> list[dict]:
    """
    Re-read the activity log from disk.
    Tolerates missing events (treats them as 0).
    """
    all_days: list[dict] = []
    current: dict | None = None

    with open(log_file, 'r') as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('[Day'):
                if current is not None:
                    all_days.append(current)
                current = {}
            elif '|' in line and current is not None:
                parts = [p.strip() for p in line.split('|')]
                name, kind, value_str = parts[0], parts[1], parts[2]
                try:
                    current[name] = int(value_str) if kind == 'D' else float(value_str)
                except ValueError:
                    pass   # skip malformed lines

    if current is not None:
        all_days.append(current)

    return all_days


# ════════════════════════════════════════════════════════════════
# Phase 3 – Analysis Engine
# ════════════════════════════════════════════════════════════════

BASELINE_FILE = "baseline_stats.txt"


def _mean_std(values: list) -> tuple[float, float]:
    n = len(values)
    if n == 0:
        return 0.0, 0.0
    mu = sum(values) / n
    variance = sum((v - mu) ** 2 for v in values) / n
    return mu, math.sqrt(variance)


def analysis_engine(all_days:  list[dict],
                     events:    dict[str, Event],
                     data_file: str = BASELINE_FILE) -> dict:
    """
    Compute daily totals, mean and std dev for each event.

    Data file format (human-readable):
        # comment
        Event: <name>
          Daily totals : [v1, v2, …]
          Mean         : <value>
          Std Dev      : <value>

    Returns baseline dict: {event_name: {'mean': …, 'std_dev': …, 'totals': […]}}
    """
    # Gather daily totals per event
    totals: dict[str, list] = {name: [] for name in events}
    for day_data in all_days:
        for name in events:
            totals[name].append(day_data.get(name, 0))

    baseline: dict = {}

    with open(data_file, 'w') as f:
        f.write("# Baseline Statistics – Email IDS\n")
        f.write("# Format: Event | Mean | Std Dev | Daily Totals\n")
        f.write("#" + "─" * 60 + "\n\n")

        print(f"\n  {'Event':<22} {'Mean':>10} {'Std Dev':>10}  Daily totals")
        print(f"  {'─'*22} {'─'*10} {'─'*10}  {'─'*30}")

        for name, values in totals.items():
            mu, sigma = _mean_std(values)
            baseline[name] = {'mean': mu, 'std_dev': sigma, 'totals': values}

            f.write(f"Event: {name}\n")
            f.write(f"  Daily totals : {values}\n")
            f.write(f"  Mean         : {mu:.4f}\n")
            f.write(f"  Std Dev      : {sigma:.4f}\n\n")

            totals_preview = str(values[:5]) + ("…" if len(values) > 5 else "")
            print(f"  {name:<22} {mu:>10.4f} {sigma:>10.4f}  {totals_preview}")

    print(f"\n  Baseline saved to '{data_file}'.")
    return baseline


# ════════════════════════════════════════════════════════════════
# Phase 4 – Alert Engine
# ════════════════════════════════════════════════════════════════

ALERT_LOG      = "alert_activity_log.txt"
ALERT_BASELINE = "alert_daily_totals.txt"


def alert_engine(events: dict[str, Event], baseline: dict):
    """
    Interactively monitor live-generated data against the baseline.

    Anomaly counter per day:
        Σ  |daily_value − baseline_mean| / baseline_std  × weight
           for each event

    Threshold = 2 × (sum of all weights)

    If anomaly_counter >= threshold → day is FLAGGED, else OK.
    """
    total_weight = sum(e.weight for e in events.values())
    threshold    = 2 * total_weight

    print(f"\n{'═'*60}")
    print(" ALERT ENGINE – Intrusion Detection")
    print(f"{'═'*60}")
    print(f"  Sum of weights : {total_weight}")
    print(f"  Threshold (2×) : {threshold}")

    while True:
        print(f"\n{'─'*60}")
        print("  [1] Load a new statistics file and run alert detection")
        print("  [2] Quit")
        choice = input("  Choice: ").strip()

        if choice == '2':
            print("\n  [Alert Engine] Exiting. Goodbye!")
            break

        if choice != '1':
            print("  Invalid choice. Enter 1 or 2.")
            continue

        # ── Collect inputs ───────────────────────────────────────
        stats_file = input("  Path to new statistics file: ").strip()
        if not os.path.isfile(stats_file):
            print(f"  File '{stats_file}' not found. Try again.")
            continue

        try:
            new_stats = parse_stats(stats_file)
        except Exception as exc:
            print(f"  Could not parse file: {exc}")
            continue

        try:
            new_days = int(input("  Number of days to simulate: ").strip())
            if new_days <= 0:
                raise ValueError
        except ValueError:
            print("  Please enter a positive integer for days.")
            continue

        # ── Generate & analyse live data ─────────────────────────
        print(f"\n[Activity Engine] Running for {new_days} day(s)…")
        live_data = activity_engine(events, new_stats, new_days, log_file=ALERT_LOG)

        print("\n[Analysis Engine] Analysing live data…")
        live_analysis = analysis_engine(live_data, events, data_file=ALERT_BASELINE)

        # ── Anomaly detection ────────────────────────────────────
        print(f"\n{'─'*60}")
        print(f"  {'Day':<6} {'Anomaly Counter':>18} {'Threshold':>12}  Status")
        print(f"  {'─'*6} {'─'*18} {'─'*12}  {'─'*10}")

        for day_idx, day_data in enumerate(live_data, start=1):
            anomaly_counter = 0.0

            for name, event in events.items():
                if name not in baseline or name not in day_data:
                    continue

                base_mean = baseline[name]['mean']
                base_std  = baseline[name]['std_dev']

                if base_std == 0:
                    # Can't normalise; skip (or treat as 0 deviation)
                    continue

                deviations       = abs(day_data[name] - base_mean) / base_std
                anomaly_counter += deviations * event.weight

            if anomaly_counter >= threshold:
                status = "FLAGGED ⚠"
            else:
                status = "okay   ✓"

            print(f"  {day_idx:<6} {anomaly_counter:>18.4f} {threshold:>12}  {status}")

        print(f"{'─'*60}")


# ════════════════════════════════════════════════════════════════
# Entry point
# ════════════════════════════════════════════════════════════════

def main():
    # ── Argument validation ──────────────────────────────────────
    if len(sys.argv) != 4:
        print("Usage: python IDS.py Events.txt Stats.txt Days")
        sys.exit(1)

    events_file = sys.argv[1]
    stats_file  = sys.argv[2]

    try:
        days = int(sys.argv[3])
        if days <= 0:
            raise ValueError
    except ValueError:
        print("Error: Days must be a positive integer.")
        sys.exit(1)

    # ════════════════════════════════════════════════════════════
    # Phase 1 – Initial Input
    # ════════════════════════════════════════════════════════════
    print("=" * 60)
    print("  CSCI262 System Security – Email IDS")
    print("=" * 60)

    # Load Events.txt
    print(f"\n[Phase 1] Loading '{events_file}'…")
    try:
        events = parse_events(events_file)
    except FileNotFoundError:
        print(f"  Error: '{events_file}' not found.")
        sys.exit(1)
    except Exception as exc:
        print(f"  Error parsing events file: {exc}")
        sys.exit(1)

    print(f"  {len(events)} event(s) loaded:")
    print_events(events)

    # Load Stats.txt
    print(f"\n[Phase 1] Loading '{stats_file}'…")
    try:
        stats = parse_stats(stats_file)
    except FileNotFoundError:
        print(f"  Error: '{stats_file}' not found.")
        sys.exit(1)
    except Exception as exc:
        print(f"  Error parsing stats file: {exc}")
        sys.exit(1)

    print(f"  {len(stats)} event stat(s) loaded:")
    print_stats(stats)

    # Consistency check
    print(f"\n[Phase 1] Consistency check…")
    issues = check_consistency(events, stats)
    if issues:
        for issue in issues:
            print(f"  {issue}")
    else:
        print("  No inconsistencies detected. ✓")

    # ════════════════════════════════════════════════════════════
    # Phase 2 – Activity Engine (baseline logging)
    # ════════════════════════════════════════════════════════════
    print(f"\n{'─'*60}")
    print("[Phase 2] Activity Engine – generating baseline events…")
    all_days = activity_engine(events, stats, days)

    # ════════════════════════════════════════════════════════════
    # Phase 3 – Analysis Engine
    # ════════════════════════════════════════════════════════════
    print(f"\n{'─'*60}")
    print("[Phase 3] Analysis Engine – computing baseline statistics…")
    baseline = analysis_engine(all_days, events)

    # ════════════════════════════════════════════════════════════
    # Phase 4 – Alert Engine
    # ════════════════════════════════════════════════════════════
    print(f"\n{'─'*60}")
    print("[Phase 4] Event generation complete. Starting alert phase…")
    alert_engine(events, baseline)


if __name__ == '__main__':
    main()
