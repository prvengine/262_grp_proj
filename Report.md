---
title: "CSCI262 System Security – Assignment 3"
subtitle: "Email System Event Modeler & Statistical Anomaly Intrusion Detection System"
author: "Devanandi Praveen (Student ID: 8575800)"
date: "SIM-2026-S2"
geometry: margin=2.5cm
fontsize: 11pt
---

# Executive Summary

This report documents the design, mathematical model, internal data architecture, and empirical verification of an Email System Event Modeler and Statistical Anomaly-based Intrusion Detection System (IDS). Developed in Python 3.12 without external dependencies, the system implements a complete pipeline across four discrete components:

1. **Initial Input Engine:** Validates and ingests configuration formats (`Events.txt`) and statistical parameters (`Stats.txt`).
2. **Activity Engine:** Simulates stochastic user and system activity over user-defined temporal windows using bounded Gaussian sampling.
3. **Analysis Engine:** Processes raw event logs into cumulative daily vectors and calculates baseline reference statistics ($\mu, \sigma$).
4. **Alert Engine:** Compares live operational activity streams against baseline profiles, calculating weighted standard deviation counters and evaluating them against a dynamic intrusion threshold.

```
                  ┌────────────────────────┐
                  │ Events.txt & Stats.txt │
                  └───────────┬────────────┘
                              │
                  ┌───────────▼────────────┐
                  │  Phase 1: Input Setup  │
                  │   & Consistency Check  │
                  └───────────┬────────────┘
                              │
                  ┌───────────▼────────────┐
                  │ Phase 2: Activity Gen  │
                  │  (Bounded Gaussian)    │
                  └───────────┬────────────┘
                              │ activity_log.txt
                  ┌───────────▼────────────┐
                  │ Phase 3: Analysis Eng  │
                  │ (Compute μ & σ)        │
                  └───────────┬────────────┘
                              │ baseline_stats.txt
                              ▼
┌──────────────────┐      ┌─────────────────────────┐
│ Live Stats Input ├─────►│  Phase 4: Alert Engine  │
└──────────────────┘      │ (Weighted Anomaly Check)│
                          └───────────┬─────────────┘
                                      │
                         ┌────────────┴────────────┐
                         ▼                         ▼
                 [okay / compliant]     [FLAGGED / Alert Raised]
```

---

# 1. Initial Input Engine

## 1.1 Internal Data Architecture & Storage

The system ingests two configuration files at startup: `Events.txt` (schema definition and anomaly weights) and `Stats.txt` (statistical behavior model). To provide optimal performance and strict type encapsulation, data is stored in object-oriented structures mapped into hash dictionaries keyed by unique event names.

### Data Classes

```python
class Event:
    """Holds structural definition and operational parameters of an event."""
    def __init__(self, name: str, kind: str,
                 minimum: float | None, maximum: float | None,
                 weight: int):
        self.name    = name     # Unique identifier (e.g., 'Logins', 'Time online')
        self.kind    = kind     # 'C' (Continuous) or 'D' (Discrete)
        self.minimum = minimum  # Lower bound across a day (None if unbounded)
        self.maximum = maximum  # Upper bound across a day (None if unbounded)
        self.weight  = weight   # Positive integer alert weighting

class EventStat:
    """Holds Gaussian distribution parameters for an event."""
    def __init__(self, name: str, mean: float, std_dev: float):
        self.name    = name     # Corresponds to Event.name
        self.mean    = mean     # Expected baseline mean (μ)
        self.std_dev = std_dev  # Expected baseline standard deviation (σ)
```

### Storage Mechanism & Computational Complexity
- **Hash Table Storage (`dict[str, Event]` and `dict[str, EventStat]`):** Provides $O(1)$ average-time complexity for event lookups during simulation iterations and daily anomaly evaluations.
- **Null-Safe Sentinel Handling:** Missing boundary limits (such as an event without an upper ceiling) are explicitly represented as `None`. This eliminates arbitrary sentinel values (e.g., `-1` or `999999`) and guarantees mathematically sound boundary enforcement.
- **Strict Format Parsing:** Each entry is parsed by splitting colon-delimited tokens (`:`), stripping leading/trailing whitespace, and enforcing strict type conversion.

---

## 1.2 Inconsistency Detection & Handling

The Initial Input Engine enforces systematic validation upon loading both files. The detected inconsistencies and operational responses are summarized below:

| Inconsistency Class | Condition Tested | System Action | Rationale |
| :--- | :--- | :---: | :--- |
| **Missing Distribution** | Event in `Events.txt` but not in `Stats.txt` | `WARNING` | Event cannot be modeled; skipped during simulation to avoid crashing. |
| **Orphan Distribution** | Event in `Stats.txt` but not in `Events.txt` | `WARNING` | Unmapped distribution parameters are ignored; system warns administrator. |
| **Count Header Mismatch** | Declared count $\ne$ parsed row count | `ERROR` / `ValueError` | Rejects malformed input files where header contradicts content. |
| **Duplicate Event Entry** | Event key declared multiple times | `ERROR` / `ValueError` | Prevents ambiguous parameter overwriting. |
| **Invalid Event Type** | Event type $\notin \{'C', 'D'\}$ | `ERROR` / `ValueError` | Halts execution; event must be discrete or continuous. |
| **Inverted Bounds** | $\text{minimum} > \text{maximum}$ | `ERROR` / `ValueError` | Logically invalid range; execution halted immediately. |
| **Non-Positive Weight** | $\text{weight} \le 0$ | `ERROR` / `ValueError` | Specification requires positive integer weights for valid threshold calculation. |
| **Negative Dispersion** | $\sigma < 0$ | `ERROR` / `ValueError` | Standard deviation must be non-negative. |
| **Infinite / NaN Values** | $\mu$ or $\sigma \in \{\pm\infty, \text{NaN}\}$ | `ERROR` / `ValueError` | Prevents arithmetic floating-point corruption. |
| **Mean Out of Range** | $\mu < \text{minimum}$ or $\mu > \text{maximum}$ | `WARNING` | Warns operator that distribution mean falls outside valid daily operational limits. |
| **Fractional Discrete Mean** | Event is 'D' and $\mu \ne \lfloor\mu\rfloor$ | `INFO` | Informational notification; daily totals are rounded to nearest whole integer. |
| **Zero Variance** | $\sigma = 0$ | `INFO` | Notifies operator that values will be deterministic at $\mu$; division-by-zero protection engaged. |

### Inconsistencies Aware of but Not Formally Blocked
- **Severe Distribution Truncation (Boundary Distortion):** When the interval $[\text{minimum}, \text{maximum}]$ is very narrow relative to $\sigma$ (e.g., width $< 1\sigma$), Gaussian values frequently clamp to the boundaries. This causes severe truncation distortion, transforming a normal distribution into boundary spikes. The engine logs boundary warnings but permits execution, allowing administrators to model tightly constrained behaviors intentionally.

---

# 2. Activity Engine and the Logs

## 2.1 Event Generation Process

The Activity Engine models synthetic daily email activity over a configurable duration of $N$ days.

### Mathematical Sampling Model
For each monitored event $e$ on day $d$, a continuous raw candidate value $X_{e,d}$ is sampled from a normal distribution parameterized by $\mu_e$ and $\sigma_e$:

$$X_{e,d} \sim \mathcal{N}(\mu_e, \sigma_e^2)$$

In Python, this is computed using `random.gauss(mean, std_dev)`, which employs the Box-Muller transform:

$$X = \mu + \sigma \sqrt{-2 \ln U_1} \cos(2\pi U_2), \quad U_1, U_2 \sim \mathcal{U}(0, 1)$$

If $\sigma = 0$, sampling is bypassed and $X_{e,d} = \mu_e$.

### Boundary Clamping & Data Type Specialization
The raw sample $X_{e,d}$ is clamped to the permitted operational domain $[\text{min}_e, \text{max}_e]$:

$$X'_{e,d} = \max\left(\text{min}_e, \, \min\left(\text{max}_e, \, X_{e,d}\right)\right)$$

The value is then specialized based on event classification:
1. **Discrete Events (`D`):** Represent individual, countable occurrences (such as logins, emails sent, emails opened, emails deleted). The clamped sample is rounded to the nearest integer and cast:
   $$V_{e,d} = \left\lfloor X'_{e,d} + 0.5 \right\rfloor \in \mathbb{Z}_{\ge 0}$$
2. **Continuous Events (`C`):** Represent cumulative or non-discrete measurements (such as total minutes spent online). Recorded to two decimal places:
   $$V_{e,d} = \frac{\left\lfloor 100 \cdot X'_{e,d} + 0.5 \right\rfloor}{100} \in \mathbb{R}$$

### Progress Reporting
To prevent terminal output congestion during long simulation runs (e.g., 365 days), progress is output dynamically using carriage returns with buffer flushing:
```python
print(f"    Day {day}/{days} logged.", end='\r', flush=True)
```
This satisfies the requirement of informative progress tracking without excessive detail.

---

## 2.2 Log File Structure and Format

The Activity Engine persists daily simulated data to `activity_log.txt`.

### Format Specification
```text
# Activity Log – Email IDS
# Format: EventName | Type (C/D) | Value
# Days: 30
#──────────────────────────────────────────────────

[Day 1]
Logins | D | 4
Time online | C | 164.32
Emails sent | D | 7
Emails opened | D | 8
Emails deleted | D | 5

[Day 2]
Logins | D | 3
Time online | C | 162.96
Emails sent | D | 7
Emails opened | D | 17
Emails deleted | D | 10
```

### Justification of Log Design
- **Human Readability & Auditability:** The pipe-delimited structure (`|`) and hierarchical `[Day N]` section headers allow security analysts to inspect logs directly in standard text viewers or command-line utilities (`grep`, `awk`, `less`).
- **Decoupling of System Engines:** The log acts as an explicit persistent contract between the Activity Engine and the Analysis Engine. Even if in-memory state is cleared or generation occurs in a separate execution, the Analysis Engine can fully reconstruct the data.
- **Embedded Schema Verification:** Storing the event type (`C`/`D`) alongside the value enables downstream validation without requiring re-reading `Events.txt`.

---

# 3. Analysis Engine

## 3.1 Data Processing and Baseline Derivation

The Analysis Engine reads `activity_log.txt` from disk via `read_log()`, reconstructs daily activity totals for each monitored event, and calculates baseline statistical metrics.

### Statistical Formulation
For each event $e$ across $N$ observed days with daily values $\{v_{e,1}, v_{e,2}, \dots, v_{e,N}\}$:

1. **Baseline Sample Mean ($\mu_e$):**
   $$\mu_e = \frac{1}{N} \sum_{d=1}^{N} v_{e,d}$$

2. **Baseline Population Standard Deviation ($\sigma_e$):**
   $$\sigma_e = \sqrt{\frac{1}{N} \sum_{d=1}^{N} (v_{e,d} - \mu_e)^2}$$

*Justification for Population Formulation:* Population standard deviation (dividing by $N$ rather than $N-1$) is chosen because the simulated baseline window represents the entire known historical population defining "normal" behavior for the monitored system, rather than an unobserved sample estimate.

---

## 3.2 Handling Incomplete Data Consistency

If a log file contains irregular records (e.g., missing events on certain days due to partial logging or truncated simulations), the engine applies resilient parsing:
- Unrecognized or corrupted lines are safely discarded without terminating the analysis.
- Missing events for any given day default to $0$, reflecting zero recorded activity.
- The engine computes statistics over all successfully parsed days, ensuring continuity even under degraded input quality.

---

## 3.3 Baseline Storage Format (`baseline_stats.txt`)

The calculated baseline statistics and complete daily vectors are serialized to `baseline_stats.txt`.

### Format Specification
```text
# Baseline Statistics – Email IDS
# Format: Event | Mean | Std Dev | Daily Totals
#────────────────────────────────────────────────────────────

Event: Logins
  Daily totals : [4, 3, 2, 5, 4, 3, 2, 4, 4, 4]
  Mean         : 3.5000
  Std Dev      : 0.9747

Event: Time online
  Daily totals : [164.32, 162.96, 143.51, 177.03, 124.56]
  Mean         : 154.4760
  Std Dev      : 19.3402
```

This human-readable key-value layout provides a permanent audit record of baseline profiles and supplies the parameters required by the Alert Engine.

---

# 4. Alert Engine

## 4.1 Intrusion Detection Workflow

The Alert Engine operates as an interactive monitoring system that compares newly observed operational data against historical baseline profiles.

```
[Interactive Prompt] ──► Select new stats file & duration
                               │
                               ▼
[Consistency Check]  ──► Validate new stats vs Events.txt
                               │
                               ▼
[Live Simulation]    ──► Generate live events (alert_activity_log.txt)
                               │
                               ▼
[Live Analysis]      ──► Compute daily totals (alert_daily_totals.txt)
                               │
                               ▼
[Anomaly Detection]  ──► Compute anomaly score per day
                               │
                               ▼
[Reporting]          ──► Compare vs Threshold: "okay" or "FLAGGED"
                               │
                               ▼
[Menu Loop]          ──► Repeat with another file or Quit
```

---

## 4.2 Anomaly Counter Mathematical Formulation

For each monitored day $d$, the engine evaluates how far each daily event total $v_{e,d}$ deviates from the established baseline mean $\mu_{e,\text{base}}$:

### Step 1: Standardized Deviation Calculation ($z_{e,d}$)
The deviation is measured in units of baseline standard deviation:

$$z_{e,d} = \frac{|v_{e,d} - \mu_{e,\text{base}}|}{\sigma_{e,\text{base}}}$$

*Defensive Safeguard:* If baseline variance is zero ($\sigma_{e,\text{base}} = 0$), $z_{e,d}$ is defined as $0$ if $v_{e,d} = \mu_{e,\text{base}}$, and $1.0$ otherwise, preventing zero-division runtime errors.

### Step 2: Weight Multiplication
Each standardized deviation is scaled by the event's configured security priority $w_e$:

$$C_{e,d} = z_{e,d} \times w_e = \left( \frac{|v_{e,d} - \mu_{e,\text{base}}|}{\sigma_{e,\text{base}}} \right) \times w_e$$

### Step 3: Total Anomaly Counter Summation
The daily anomaly score $A_d$ is the sum of weighted deviations across all monitored events $E$:

$$A_d = \sum_{e \in E} C_{e,d} = \sum_{e \in E} \left( \frac{|v_{e,d} - \mu_{e,\text{base}}|}{\sigma_{e,\text{base}}} \times w_e \right)$$

---

## 4.3 Threshold Determination & Decision Rule

### Threshold Formula
The intrusion threshold $T$ is defined as twice the sum of all event weights:

$$T = 2 \times \sum_{e \in E} w_e$$

For the baseline configuration:
$$\sum w_e = 2 (\text{Logins}) + 3 (\text{Time online}) + 1 (\text{Emails sent}) + 1 (\text{Emails opened}) + 2 (\text{Emails deleted}) = 9$$
$$T = 2 \times 9 = 18.00$$

### Decision Rule
- If $A_d \ge T \implies$ **FLAGGED (alert) ⚠** (Intrusion / anomalous behavior detected)
- If $A_d < T \implies$ **okay ✓** (Activity within acceptable bounds)

### Step-by-Step Trace (Specification Verification)
Consider an individual day where daily logins $v = 1$.
- Baseline parameters: $\mu = 4.0$, $\sigma = 1.5$, weight $w = 2$.
- Standard deviation distance:
  $$z = \frac{|1 - 4.0|}{1.5} = \frac{3.0}{1.5} = 2.0 \text{ standard deviations}$$
- Weighted contribution:
  $$C = 2.0 \times 2 = 4.0$$
*(Note: Assignment text page 5 states "contributes $2 \times 2 = 42$", where $42$ represents a typographical concatenation of the answer $4$ and footnote marker $2$. The calculated value of $4.0$ confirms mathematical correctness).*

---

## 4.4 Empirical Verification & Evaluation

The system was verified against both compliant operational datasets and simulated intrusion attacks.

### Scenario A: Normal Operating Activity (`Stats_normal.txt`)
Parameters match baseline expectation ($\mu_{\text{login}} = 4.0, \sigma = 1.5$):

```text
═════════════════════════════════════════════════════════════════
  Day     Anomaly Counter    Threshold  Status
  ────── ────────────────── ────────────  ────────────────────
  1                  3.3472        18.00  okay            ✓
  2                 12.0247        18.00  okay            ✓
  3                 12.3829        18.00  okay            ✓
  4                 12.3357        18.00  okay            ✓
  5                  4.9975        18.00  okay            ✓
═════════════════════════════════════════════════════════════════
Result: 0 / 5 days flagged (100% compliant, zero false positives).
```

### Scenario B: Account Compromise & Bulk Exfiltration (`Stats_anomalous.txt`)
Simulates compromised credentials: Logins $\mu = 50$, Time online $\mu = 1400$, Emails sent $\mu = 200$:

```text
═════════════════════════════════════════════════════════════════
  Day     Anomaly Counter    Threshold  Status
  ────── ────────────────── ────────────  ────────────────────
  1                192.4180        18.00  FLAGGED (alert) ⚠
  2                210.1542        18.00  FLAGGED (alert) ⚠
  3                188.7619        18.00  FLAGGED (alert) ⚠
═════════════════════════════════════════════════════════════════
Result: 3 / 3 days flagged (100% detection rate of intrusion activity).
```

---

# 5. Compilation, Execution & Submission

## 5.1 Environment & Execution Instructions

The project is implemented in pure Python 3.12 (compatible with Python 3.11+) and requires no external libraries.

### Execution Syntax
```bash
# Direct Python execution:
python3 IDS.py Events.txt Stats.txt 30

# Or via the executable wrapper script:
chmod +x IDS
./IDS Events.txt Stats.txt 30
```

## 5.2 Verification Checklist

- [x] Initial setup command-line interface (`IDS Events.txt Stats.txt Days`).
- [x] Strict input validation for counts, event types, positive weights, bounds, and finite distributions.
- [x] Generation of human-readable `activity_log.txt`.
- [x] Complete decoupling: Analysis Engine reads from disk via `read_log()`.
- [x] Daily totals and statistical models stored in `baseline_stats.txt`.
- [x] Interactive Alert Engine with dynamic threshold calculation ($2 \times \sum w$).
- [x] Automatic validation of live statistics files before alert simulation.
- [x] Clean submission archive (`submission.zip`) with **zero subdirectories**.
