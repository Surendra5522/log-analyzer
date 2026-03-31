# Log Analyzer

A lightweight C++ tool that parses Linux authentication logs and detects 
SSH brute force attacks in real time.

## Compilation
```bash
g++ loganalyzer.cpp -o loganalyzer
```

## Usage
```bash
./loganalyzer <path-to-logfile>
```

## Example
```bash
./loganalyzer auth.log
```
Output:
```
Brute Force attempt detected from 192.168.1.10
```

## How It Works
The tool parses each line of the log file and extracts the source IP 
and timestamp from failed SSH login attempts. Timestamps are converted 
to seconds and stored in a map keyed by IP address. A sliding window 
algorithm then checks if any IP has 6 or more failed attempts within 
a 60-second window — if so, it is flagged as a brute force attack.

## Detection Rules
- **Brute Force**: 6+ failed login attempts from the same IP within 60 seconds

## Tech Stack
- C++
- STL (map, vector, string)
- Sliding Window Algorithm