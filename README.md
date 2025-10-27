# Quick CTI - MITRE ATT&CK Threat Group STIX Extractor

A Python tool for extracting STIX 2.0 data and generating threat hunting queries for specific threat actors from the MITRE ATT&CK Enterprise framework.

## Overview

Quick CTI automates the process of gathering cyber threat intelligence (CTI) about specific threat groups from MITRE ATT&CK and generates actionable threat hunting queries. The tool fetches the latest MITRE ATT&CK Enterprise data, extracts techniques and tools associated with a specified threat group, and produces SQL-based hunting queries for use in security operations.

## Features

- **STIX 2.0 Bundle Generation**: Creates complete STIX bundles containing threat group data, techniques, software, and relationships
- **Comprehensive Reporting**: Generates detailed JSON reports with technique mappings, tactics, and software usage
- **Threat Hunting Queries**: Produces SQL-based hunting queries across four categories:
  - Simple IOC searches
  - Behavioral pattern detections
  - Chained event correlations
  - Anomaly-based detections
- **Interactive & CLI Modes**: Supports both interactive prompts and command-line arguments
- **Group Discovery**: List all available threat groups in MITRE ATT&CK
- **Alias Support**: Search by threat group name or known aliases

## Requirements

- Python 3.7+
- `requests` library

## Installation

1. Clone this repository:
```bash
git clone https://github.com/EricS-Arbitr/quick_cti.git
cd quick_cti
```

2. Install dependencies:
```bash
pip install requests
```

## Usage

### Basic Usage

Extract data for a specific threat group:
```bash
python quick_cti.py APT29
```

For multi-word names, use quotes:
```bash
python quick_cti.py "Lazarus Group"
```

### List All Available Threat Groups

```bash
python quick_cti.py list
```

### Interactive Mode

Run without arguments to enter interactive mode:
```bash
python quick_cti.py
```

### Command-Line Options

```
usage: quick_cti.py [-h] [-v] [threat_group ...]

positional arguments:
  threat_group   Name or alias of the threat group (e.g., APT29, "Lazarus Group")
                 Use "list" to show all available groups

optional arguments:
  -h, --help     show this help message and exit
  -v, --version  show program's version number and exit
```

## Output Files

The tool generates three JSON files per threat group:

### 1. STIX Bundle
**Filename**: `mitre_<group>_stix_<timestamp>.json`

Contains the complete STIX 2.0 bundle with:
- Threat actor (intrusion-set) object
- Attack patterns (techniques) used by the group
- Software/malware objects
- Relationship objects linking everything together

### 2. Summary Report
**Filename**: `mitre_<group>_report_<timestamp>.json`

Detailed analysis including:
- Threat group metadata (name, aliases, description)
- Complete list of techniques with MITRE ATT&CK IDs
- Tactics mapping
- Software and tools used
- Technique counts and statistics

### 3. Hunt Queries
**Filename**: `mitre_<group>_hunt_queries_<timestamp>.json`

SQL-based threat hunting queries organized by detection type:

#### Simple IOC Searches
Quick searches for known malware/tools in process logs

#### Behavioral Pattern Detections
Technique-specific detections for common TTPs:
- T1566: Phishing detection
- T1059.001: PowerShell execution patterns
- T1071: C2 beaconing behavior
- T1055: Process injection
- T1003: Credential dumping
- T1053: Scheduled task persistence

#### Chained Event Detections
Multi-stage attack correlations:
- Initial Access → Execution → Persistence
- Execution → Discovery → Lateral Movement
- Credential Access → Collection → Exfiltration
- PowerShell Execution → C2 Callback

#### Anomaly-Based Detections
Baseline-required detections:
- Rare process-parent relationships
- Unusual outbound connections
- Off-hours activity

## Example Output

```
======================================================================
MITRE ATT&CK Threat Group STIX Extractor
======================================================================

[*] Fetching MITRE ATT&CK Enterprise data...
[+] Successfully fetched 15234 STIX objects

[*] Searching for threat group: APT29
[+] Found: APT29
    ID: intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542
    Aliases: APT29, YTTRIUM, The Dukes, Cozy Bear
    Description: APT29 is threat group that has been attributed to...

[+] Found 87 techniques
[+] Found 23 software/tools

[+] STIX bundle saved: mitre_APT29_stix_20241027_143022.json
[+] Summary report saved: mitre_APT29_report_20241027_143022.json
[+] Hunt queries saved: mitre_APT29_hunt_queries_20241027_143022.json
```

## Recommended Log Sources

For optimal hunting results, ensure you have access to:

- **Windows Event Logs**: Security (4688, 4698), System, Application
- **Sysmon**: Events 1, 3, 7, 8, 10, 11
- **PowerShell Logs**: Event 4104 (Script Block Logging)
- **Network Logs**: Firewall, Proxy, NetFlow, Zeek/Bro
- **Email Gateway Logs**: For phishing detection
- **EDR/XDR Telemetry**: Comprehensive endpoint visibility

## Hunt Strategy

The tool provides a recommended hunt strategy in five phases:

1. **Immediate Actions (Day 1)**: Run simple IOC searches
2. **Behavioral Hunting (Days 2-3)**: Deploy technique-specific detections
3. **Correlation Hunting (Week 1)**: Implement chained event detections
4. **Continuous Monitoring**: Establish baselines and anomaly detection
5. **Intelligence Updates**: Re-run hunts when new intel is published

## Use Cases

- **Retrospective Threat Hunting**: Search historical logs for evidence of specific threat actors
- **Proactive Detection**: Deploy monitoring for known threat group TTPs
- **Incident Response**: Quickly understand a threat actor's techniques during an investigation
- **Purple Teaming**: Generate test scenarios based on real threat actor behavior
- **Security Operations**: Enrich SIEM/EDR detection rules with threat intelligence

## Data Source

This tool fetches data from the official MITRE ATT&CK repository:
```
https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

## Limitations

- Requires internet connection to fetch MITRE ATT&CK data
- SQL queries are generic templates and may require customization for your specific environment
- Query table names and field names should be adapted to your log schema
- Baseline-required anomaly queries need historical data to be effective

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This tool is provided as-is for cybersecurity defense and research purposes.

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [STIX 2.0 Specification](https://docs.oasis-open.org/cti/stix/v2.0/stix-v2.0-part1-stix-core.html)
- [MITRE CTI Repository](https://github.com/mitre/cti)

## Disclaimer

This tool is intended for authorized security operations, threat hunting, and defensive cybersecurity purposes only. Ensure you have proper authorization before conducting threat hunting activities on any network or system.
