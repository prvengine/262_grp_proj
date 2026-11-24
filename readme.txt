CSCI262 System Security – Assignment 3
Email System Event Modeler & Intrusion Detection System
=======================================================

Group Members & Student IDs : Devanandi Praveen (8575800)
Language      : Python 3.12.4

No third-party libraries are required. Only Python standard-library modules
are used: sys, os, math, random.

─────────────────────────────────────────────────────
COMPILATION / INSTALLATION
─────────────────────────────────────────────────────

Python does not require compilation.

1. Ensure Python 3.11 or later is installed:
     python3 --version

   If not installed, download from https://www.python.org/downloads/

2. No pip install or additional setup is needed. The program runs directly.

─────────────────────────────────────────────────────
HOW TO RUN
─────────────────────────────────────────────────────

Command syntax:
  python3 IDS.py <Events.txt> <Stats.txt> <Days>

Or via the included executable wrapper script:
  chmod +x IDS
  ./IDS <Events.txt> <Stats.txt> <Days>

Arguments:
  Events.txt  – path to the events definition file
  Stats.txt   – path to the statistics/distribution file
  Days        – positive integer; number of days to use for baseline generation

Example:
  python3 IDS.py Events.txt Stats.txt 30
  (or: ./IDS Events.txt Stats.txt 30)

Note: On some systems the command may be "python" instead of "python3".
      Use whichever resolves to Python 3.11+ on your machine.

─────────────────────────────────────────────────────
PROGRAM PHASES
─────────────────────────────────────────────────────

Phase 1 – Initial Input
  Loads and displays Events.txt and Stats.txt.
  Runs consistency checks and reports any warnings.

Phase 2 – Activity Engine
  Generates simulated events for <Days> days using Gaussian distributions.
  Writes a human-readable log to: activity_log.txt

Phase 3 – Analysis Engine
  Reads the activity log, computes daily totals, mean and std dev per event.
  Writes baseline statistics to: baseline_stats.txt

Phase 4 – Alert Engine  (interactive)
  Prompts for a new statistics file and a number of alert days.
  Generates live data, compares against the baseline, and reports each day
  as "okay" or "FLAGGED" based on the anomaly counter vs. threshold.
  Loops until the user selects the quit option.

─────────────────────────────────────────────────────
OUTPUT FILES PRODUCED
─────────────────────────────────────────────────────

  activity_log.txt       – baseline event log (Phase 2)
  baseline_stats.txt     – mean & std dev per event (Phase 3)
  alert_activity_log.txt – live-data log for alert sessions (Phase 4)
  alert_daily_totals.txt – daily totals for alert sessions (Phase 4)

─────────────────────────────────────────────────────
SUBMISSION FILES
─────────────────────────────────────────────────────

  IDS.py       – main program (all four phases)
  IDS          – executable bash wrapper script (optional convenience)
  Events.txt   – sample events definition file
  Stats.txt    – sample statistics file
  readme.txt   – this file
  Report.pdf   – project report
