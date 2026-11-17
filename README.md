# Log Analyzer and Threat Detector

A Python-based security log analysis tool that processes authentication logs, identifies failed login attempts, and flags potentially suspicious IP addresses based on a configurable threshold.

## Project Overview

This project demonstrates the use of Python for basic security log analysis. It reads authentication records from a log file, categorises successful and failed login attempts, tracks failed attempts by IP address, and identifies IP addresses that meet a defined suspicious activity threshold.

The project uses synthetic authentication data for demonstration and testing.

## Features

- Parses authentication log records.
- Counts successful and failed login attempts.
- Tracks failed login attempts by IP address.
- Identifies potentially suspicious IP addresses using a configurable threshold.
- Handles malformed records and unknown login statuses.
- Handles missing log files.
- Generates a text-based security analysis report.
- Includes automated unit tests using Python's `unittest` framework.

## Project Structure

```text
log-analyzer-threat-detector/
│
├── data/
│   └── sample_auth.log
│
├── src/
│   └── log_analyzer.py
│
├── reports/
│   └── .gitkeep
│
├── tests/
│   ├── __init__.py
│   └── test_log_analyzer.py
│
├── README.md
├── requirements.txt
└── .gitignore
```

## Technologies Used

- Python 3
- Python standard library
- File handling and exception handling
- Dictionaries and data processing
- Unit testing with `unittest`
- Git and GitHub

## How It Works

1. The program reads authentication records from `data/sample_auth.log`.
2. Each record is parsed to extract the timestamp, username, IP address, and login status.
3. Successful and failed login attempts are counted separately.
4. Failed attempts are grouped by IP address.
5. IP addresses meeting the configured threshold are flagged as potentially suspicious.
6. A security analysis report is generated in the `reports/` directory.

## How to Run

**Prerequisites:** Python 3 installed on your system.

Clone the repository:

git clone https://github.com/yadarsh47-source/log-analyzer-threat-detector.git

Navigate to the project directory:

```bash
cd log-analyzer-threat-detector
```

Run the program:

```bash
python src/log_analyzer.py
```

The generated report will be saved as:

```text
reports/security_report.txt
```

## Running the Tests

Run the automated unit tests from the project root:

```bash
python -m unittest discover -s tests -p "test_log_analyzer.py" -v
```

The test suite covers:

- Authentication log analysis.
- Suspicious IP detection.
- Malformed record handling.
- Missing log file handling.
- Security report generation.

## Sample Analysis Results

Using the supplied synthetic authentication log:

| Metric | Result |
|---|---:|
| Total successful logins | 5 |
| Total failed logins | 9 |
| Suspicious IP addresses identified | 3 |

The default detection threshold is three failed login attempts per IP address.

## Limitations and Future Enhancements

This is an educational project demonstrating fundamental security log analysis techniques. It does not establish whether an IP address is malicious or perform real-time intrusion detection.

Potential future enhancements include:

- Timestamp and IP address validation.
- Detection of repeated failures within a defined time window.
- Analysis of larger log datasets.
- Support for additional log formats.
- Visualisation of authentication trends.
- More advanced anomaly detection techniques.

## Disclaimer

The project uses synthetic authentication records and is intended for educational purposes. It should not be considered a production-grade security monitoring or intrusion detection system.