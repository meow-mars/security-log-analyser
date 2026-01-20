# Security Log Analyser (Python)

A Python-based security log analyser that detects suspicious login behaviour
using time-window analysis.

## Features
- Parses authentication logs
- Tracks failed login attempts per user and IP
- Detects brute-force attempts (3+ failures within 5 minutes)
- Generates real-time alerts
- Exports alerts to a persistent log file

## Example Alert
2026-01-12 22:47:20 | ALERT | USER: john | IP address: 10.0.0.5 | Attempts: 3 | Window: 5 minutes | IP Type: PRIVATE | Severity: HIGH
2026-01-12 22:57:23 | ALERT | USER: john | IP address: 12.0.0.6 | Attempts: 3 | Window: 5 minutes | IP Type: PUBLIC | Severity: MEDIUM

## Skills Demonstrated
- Python dictionaries & list comprehension
- datetime & timedelta usage
- Security event detection logic
- Log analysis fundamentals

## Alert Severity (RFC1918 IP ranges)
- HIGH: Internal (private) IP brute-force attempts
- MEDIUM: External (public) IP brute-force attempts
