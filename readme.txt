CSCI262 System Security – Assignment 3
Email System Event Modeler & Intrusion Detection System
=======================================================

Group Members & Student IDs : Devanandi Praveen (8575800),
Language      : Python 3

No third-party libraries are required. Only Python standard-library modules
are used: sys, math, random, dataclasses.

─────────────────────────────────────────────────────
COMPILATION / INSTALLATION
─────────────────────────────────────────────────────

Python does not require compilation.

1. Ensure Python 3.8 or later is installed:
     python3 --version

   If not installed, download from https://www.python.org/downloads/

2. No pip install or additional setup is needed. The program runs directly.

─────────────────────────────────────────────────────
HOW TO RUN
─────────────────────────────────────────────────────

Command syntax:
  python3 ids.py <Events.txt> <Stats.txt> <Days>

Arguments:
  Events.txt  – path to the events definition file
  Stats.txt   – path to the statistics/distribution file
  Days        – positive integer; number of days to use for baseline generation

Example:
  python3 ids.py Events.txt Stats.txt 30

Note: On some systems the command may be "python" instead of "python3".
      Use whichever resolves to Python 3.8+ on your machine.

─────────────────────────────────────────────────────
PROGRAM PHASES
─────────────────────────────────────────────────────

Phase 1 – Initial Input
  Loads and displays Events.txt and Stats.txt.
  Runs consistency checks and reports any warnings.

Phase 2 – Activity Engine
  Generates simulated events for <Days> days using Gaussian distributions.
  Writes a human-readable log to: BaselineLog.txt

Phase 3 – Analysis Engine
  Reads the activity log, computes daily totals, mean and std dev per event.
  Writes daily totals to: BaselineDailyTotals.txt
  Writes baseline statistics to: BaselineStats.txt

Phase 4 – Alert Engine  (interactive)
  Prompts for a new statistics file and a number of alert days.
  Generates live data, compares against the baseline, and reports each day
  as "okay" or "FLAGGED" based on the anomaly counter vs. threshold.
  Loops until the user enters 'q' to quit.

─────────────────────────────────────────────────────
OUTPUT FILES PRODUCED
─────────────────────────────────────────────────────

  BaselineLog.txt          – baseline event log (Phase 2)
  BaselineDailyTotals.txt  – daily totals per event (Phase 3)
  BaselineStats.txt        – mean & std dev per event (Phase 3)
  LiveLog.txt              – live-data log for alert sessions (Phase 4)

─────────────────────────────────────────────────────
SUBMISSION FILES
─────────────────────────────────────────────────────

  ids.py           – main program (all four phases)
  Events.txt       – events definition file
  Stats.txt        – statistics file
  Stats_attack.txt – attack statistics file (for testing)
  readme.txt       – this file
  Report.pdf       – project report
