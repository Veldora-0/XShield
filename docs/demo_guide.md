# XShield Live Demonstration Guide

This guide uses only local inputs and the existing application. The example
outputs below were produced during an isolated demonstration with a temporary
SQLite database; live values such as event IDs and timestamps may differ.
Submitted strings are treated as data and are never executed.

## Step 1 - Start the Application

From the project root in PowerShell:

```powershell
$env:XSHIELD_DASHBOARD_USERNAME = "admin"
$env:XSHIELD_DASHBOARD_PASSWORD = "choose-a-local-password"
.\.venv\Scripts\python.exe -m app
```

The application starts with debug disabled by default. Keep the terminal
visible during the demonstration so startup errors are observable.

## Step 2 - Open the XShield Interface

Open <http://127.0.0.1:5000/> and show the input workspace. Explain that the
server validates the username, search query, and comment before the pipeline
receives them.

## Step 3 - Submit a Benign Example

Use:

```text
Username:     demo_student
Search Query: library opening hours
Comment:      The search page is easy to use.
```

Expected behavior from the recorded local demonstration:

| Output | Observed value |
|---|---:|
| Rule score | 0.0 |
| ML prediction | `benign` |
| ML XSS probability | 0.0671523208 |
| Hybrid signal | 0.0335761604 |
| Risk score | 3.36 / 100 |
| Risk level | Low |
| Action | `allow` |
| Agreement | `both_benign` |

Explain that a low risk result still follows the safe escaped-text display
path. The result is an assessment, not proof that text is universally safe.

## Step 4 - Submit a Local Security-Test Example

Use this local defensive test string as data:

```text
Username:     demo_student
Search Query: security review
Comment:      <img src="javascript:demo" onerror="run()">
```

Do not place this text in a real external website and do not execute it.

Observed output from the isolated demonstration:

| Output | Observed value |
|---|---:|
| Rule score | 77.0 |
| Matched rules | `R001`, `R003`, `R004`, `R006` |
| ML prediction | `xss` |
| ML XSS probability | 0.9826289385 |
| Hybrid signal | 0.8763144693 |
| Risk score | 87.63 / 100 |
| Risk level | Critical |
| Action | `block_and_alert` |
| Agreement | `both_suspicious` |

Explain the evidence: markup, an event-handler-style attribute, a suspicious
URL scheme, and multiple indicators were matched. The action is local
application behavior. No firewall, IP blocking, network termination, or
external alert occurs.

The result page suppresses the submitted content when the action is blocking,
while the security event remains available for review.

## Step 5 - Open the Dashboard

Open <http://127.0.0.1:5000/dashboard> and enter the configured Basic
Authentication credentials.

Show:

- total event count;
- Low, Medium, High, and Critical distribution;
- blocked event count;
- newest-first event table;
- risk and action filters.

The isolated demonstration produced:

```text
Total events: 2
Low: 1
Medium: 0
High: 0
Critical: 1
Blocked: 1
```

## Step 6 - Open an Event Detail

Select the suspicious event ID from the recent-events table. Show:

- UTC timestamp and event ID;
- rule score, matched rule IDs, and rule reasons;
- ML prediction and probability;
- hybrid signal, weights, and agreement;
- risk score and risk level;
- response action;
- stored reasons.

Point out that stored input is rendered as escaped text. The event detail route
uses the same dashboard authentication as the dashboard route.

## Step 7 - Show Evaluation Results

Run the comparative evaluation from a second terminal:

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_all.py
```

Explain that all methods use the same 3,967-row held-out test set and that the
vectorizer/model are loaded rather than retrained.

| Method | Accuracy | Precision | Recall | F1 | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Rule-Based | 0.9979833627 | 1.0000000000 | 0.9245283019 | 0.9607843137 | 0 | 8 |
| ML | 0.9989916814 | 1.0000000000 | 0.9622641509 | 0.9807692308 | 0 | 4 |
| Hybrid | 0.9979833627 | 1.0000000000 | 0.9245283019 | 0.9607843137 | 0 | 8 |

Explain:

- precision describes how many predicted XSS records were actually XSS;
- recall describes how many XSS records were found;
- F1 combines precision and recall;
- a confusion matrix separates true/false positives and negatives;
- these are test-set results, not real-world guarantees.

## Demo Notes

- Keep all demonstrations local.
- Do not paste the test string into an external site.
- Do not describe `block_and_alert` as a real alert.
- Do not claim that any method detects every XSS attack.
- Use the actual event values shown by the current run if the database already
  contains earlier events.
