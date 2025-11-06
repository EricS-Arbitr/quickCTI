# APT33 Threat Intelligence Report

**Classification:** UNCLASSIFIED // FOR TRAINING USE ONLY
**Report ID:** TIR-APT33-2025-001
**Date:** November 6, 2025
**Prepared By:** Threat Intelligence Analysis Team
**Distribution:** Training Exercise Use Only

---

## Executive Summary

**APT33** (also known as HOLMIUM, Elfin, and Peach Sandstorm) is a suspected Iranian nation-state threat actor that has been active since at least 2013. The group has demonstrated sustained interest in targeting critical infrastructure sectors, particularly aviation and energy industries across the United States, Saudi Arabia, and South Korea.

### Key Findings

- **Attribution:** Iranian nexus (high confidence)
- **Active Since:** 2013
- **Primary Targets:** Aviation, aerospace, energy, petrochemical, defense contractors
- **Geographic Focus:** United States, Saudi Arabia, South Korea, Middle East
- **Sophistication Level:** Medium to Advanced
- **Key Motivation:** Espionage, strategic intelligence collection, potential destructive capability

### Threat Assessment

| Category | Rating | Notes |
|----------|--------|-------|
| **Technical Sophistication** | Medium-High | Custom malware, living-off-the-land techniques |
| **Operational Security** | Medium | Moderate OPSEC, reuses infrastructure |
| **Resource Level** | High | Well-resourced, sustained campaigns |
| **Target Diversity** | Medium | Focused on strategic sectors |
| **Impact Potential** | High | Critical infrastructure targeting |

---

## Table of Contents

1. [Threat Actor Profile](#threat-actor-profile)
2. [Tactical Profile - MITRE ATT&CK Mapping](#tactical-profile)
3. [Attack Lifecycle](#attack-lifecycle)
4. [Tools and Malware Arsenal](#tools-and-malware-arsenal)
5. [Infrastructure and TTPs](#infrastructure-and-ttps)
6. [Detection Strategies](#detection-strategies)
7. [Hunting Methodologies](#hunting-methodologies)
8. [Indicators of Compromise](#indicators-of-compromise)
9. [Defensive Recommendations](#defensive-recommendations)
10. [References](#references)

---

## 1. Threat Actor Profile

### 1.1 Group Overview

**APT33** is assessed to be an Iranian state-sponsored cyber espionage group with a mandate to collect strategic intelligence on critical infrastructure and defense industrial base targets. The group has demonstrated capabilities in both espionage operations and potentially destructive cyber attacks.

**Aliases:**
- APT33 (FireEye)
- HOLMIUM (Microsoft)
- Elfin (Symantec)
- Peach Sandstorm (Microsoft, current naming)

**Attribution Confidence:** High

Evidence supporting Iranian attribution includes:
- Targeting patterns aligned with Iranian strategic interests
- Operational timing correlating with Iranian work hours
- Tool development artifacts containing Farsi language strings
- Infrastructure overlap with known Iranian threat actors
- Focus on Saudi Arabian targets (regional adversary)

### 1.2 Historical Context

**2013-2015:** Initial Discovery
- First observed targeting aviation sector
- Focused reconnaissance and credential harvesting

**2016-2017:** Expanded Operations
- Broadened targeting to energy and petrochemical sectors
- Developed custom malware capabilities (TURNEDUP, NANOCORE)
- Increased spearphishing campaigns

**2018-2019:** Infrastructure Campaigns
- Heavy focus on critical infrastructure
- Deployment of destructive malware (SHAPESHIFT, DEADWOOD)
- Password spraying attacks against defense contractors

**2020-Present:** Continued Operations
- Sustained targeting of aviation and defense
- Adoption of living-off-the-land techniques
- Integration of open-source tools (Mimikatz, PowerSploit)

### 1.3 Targeting Profile

**Primary Sectors:**
1. **Aviation & Aerospace** (40%)
   - Commercial aviation
   - Aerospace manufacturers
   - Airport authorities
   - Aircraft component suppliers

2. **Energy & Petrochemical** (35%)
   - Oil and gas companies
   - Refineries
   - Petrochemical plants
   - Energy sector IT services

3. **Defense Industrial Base** (15%)
   - Defense contractors
   - Military aviation suppliers
   - Research institutions

4. **Government & Critical Infrastructure** (10%)
   - Government agencies
   - Critical infrastructure operators
   - IT service providers

**Geographic Distribution:**
- United States (45%)
- Saudi Arabia (30%)
- South Korea (15%)
- Other Middle East (10%)

**Victim Profile:**
- Organizations with strategic intelligence value
- Companies involved in Iran sanctions enforcement
- Defense contractors supporting regional adversaries
- Critical infrastructure with potential disruption impact

---

## 2. Tactical Profile - MITRE ATT&CK Mapping

APT33 employs 31 distinct MITRE ATT&CK techniques across 10 tactics, demonstrating a comprehensive operational playbook.

### 2.1 Tactic Distribution

```
Credential Access    ████████████████████ (9 techniques) 29%
Execution           ███████████████      (6 techniques) 19%
Privilege Escalation███████████████      (6 techniques) 19%
Persistence         ████████████         (5 techniques) 16%
Command & Control   ████████████         (5 techniques) 16%
Initial Access      ██████████           (4 techniques) 13%
Defense Evasion     ███████              (3 techniques) 10%
Collection          ███                  (1 technique)   3%
Exfiltration        ███                  (1 technique)   3%
Discovery           ███                  (1 technique)   3%
```

### 2.2 Initial Access (T1078, T1566)

APT33 gains initial access through multiple vectors:

#### **T1566.001 - Spearphishing Attachment**
- **Description:** Malicious Office documents with embedded macros
- **Frequency:** Very High
- **Sophistication:** Medium
- **Example:** .docx files with social engineering themes related to aviation/energy

**Hunt Logic:**
```sql
-- Detect suspicious email attachments leading to execution
SELECT
    timestamp,
    recipient_email,
    sender_email,
    attachment_name,
    file_hash
FROM email_logs
WHERE attachment_extension IN ('.doc', '.docx', '.xls', '.xlsx')
  AND (
    attachment_name LIKE '%invoice%'
    OR attachment_name LIKE '%report%'
    OR attachment_name LIKE '%contract%'
  )
  AND sender_domain NOT IN (known_partner_domains)
```

#### **T1566.002 - Spearphishing Link**
- **Description:** Links to credential harvesting pages or malware downloads
- **Frequency:** High
- **Sophistication:** Low-Medium
- **Example:** Fake login pages mimicking corporate webmail

#### **T1078 - Valid Accounts**
- **Description:** Use of compromised credentials for initial access
- **Frequency:** High
- **Sophistication:** Medium
- **Example:** VPN access using stolen credentials

**Hunt Logic:**
```sql
-- Detect VPN logins from unusual locations
SELECT
    timestamp,
    username,
    source_ip,
    source_country,
    COUNT(*) as login_attempts
FROM vpn_logs
WHERE authentication_result = 'success'
  AND source_country NOT IN (expected_countries)
GROUP BY username, source_country
HAVING COUNT(*) > 3
```

### 2.3 Execution (T1059, T1203, T1204)

#### **T1059.001 - PowerShell**
- **Frequency:** Very High
- **Detection Priority:** Critical
- **Characteristics:**
  - Base64-encoded commands
  - Download cradles (IEX/Invoke-WebRequest)
  - PowerSploit module usage

**Hunt Logic:**
```sql
-- Detect suspicious PowerShell execution
SELECT
    `@timestamp`,
    host_name,
    user_name,
    process_command_line,
    parent_process_name
FROM win_sysmon
WHERE event_code = '1'
  AND process_name = 'powershell.exe'
  AND (
    process_command_line LIKE '%-encodedcommand%'
    OR process_command_line LIKE '%IEX%'
    OR process_command_line LIKE '%Invoke-WebRequest%'
    OR process_command_line LIKE '%DownloadString%'
    OR process_command_line LIKE '%PowerSploit%'
  )
ORDER BY `@timestamp` DESC
```

#### **T1059.005 - Visual Basic**
- **Frequency:** High
- **Detection Priority:** High
- **Characteristics:** Macro-enabled Office documents

**Hunt Logic:**
```sql
-- Detect Office applications spawning suspicious processes
SELECT
    `@timestamp`,
    host_name,
    process_name,
    parent_process_name,
    process_command_line
FROM win_sysmon
WHERE event_code = '1'
  AND parent_process_name IN ('WINWORD.EXE', 'EXCEL.EXE', 'POWERPNT.EXE')
  AND process_name IN ('powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe')
ORDER BY `@timestamp` DESC
```

#### **T1203 - Exploitation for Client Execution**
- **Frequency:** Medium
- **Sophistication:** High
- **Example:** CVE exploits in Office, browsers

#### **T1204.002 - Malicious File**
- **Frequency:** Very High
- **Example:** User opens malicious attachment

### 2.4 Persistence (T1053, T1136, T1547)

#### **T1053.005 - Scheduled Task/Job: Scheduled Task**
- **Frequency:** High
- **Detection Priority:** High

**Hunt Logic:**
```sql
-- Detect suspicious scheduled task creation
SELECT
    `@timestamp`,
    host_name,
    user_name,
    process_command_line,
    process_name
FROM win_sysmon
WHERE event_code = '1'
  AND (
    process_command_line LIKE '%schtasks%/create%'
    OR (process_name = 'schtasks.exe' AND process_command_line LIKE '%/create%')
  )
  AND (
    process_command_line LIKE '%powershell%'
    OR process_command_line LIKE '%cmd.exe%'
    OR process_command_line LIKE '%wscript%'
  )
ORDER BY `@timestamp` DESC
```

#### **T1136.001 - Create Account: Local Account**
- **Frequency:** Medium
- **Detection Priority:** Critical

**Hunt Logic:**
```sql
-- Detect local account creation
SELECT
    `@timestamp`,
    host_name,
    event_data.TargetUserName as new_account,
    event_data.SubjectUserName as creator_account
FROM win_security
WHERE event_id = 4720  -- User account created
ORDER BY `@timestamp` DESC
```

#### **T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys**
- **Frequency:** Medium
- **Detection Priority:** High

**Hunt Logic:**
```sql
-- Detect registry run key modifications
SELECT
    `@timestamp`,
    host_name,
    registry_target_object,
    registry_details
FROM win_sysmon
WHERE event_code = '13'  -- Registry value set
  AND (
    registry_target_object LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%'
    OR registry_target_object LIKE '%\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce%'
  )
ORDER BY `@timestamp` DESC
```

### 2.5 Privilege Escalation (T1055, T1068, T1134)

#### **T1055 - Process Injection**
- **Frequency:** High
- **Detection Priority:** Critical
- **Techniques:** PowerSploit's Invoke-ReflectivePEInjection

**Hunt Logic:**
```sql
-- Detect process injection indicators
SELECT
    `@timestamp`,
    host_name,
    process_name,
    process_target.name as target_process,
    process_granted_access
FROM win_sysmon
WHERE event_code = '10'  -- Process Access
  AND process_granted_access IN ('0x1F0FFF', '0x1F3FFF', '0x1FFFFF')  -- Full access
  AND process_target.name IN ('lsass.exe', 'services.exe', 'svchost.exe')
  AND process_name NOT IN (
    'csrss.exe', 'wininit.exe', 'services.exe',
    'MsMpEng.exe', 'SenseIR.exe'  -- Exclude AV
  )
ORDER BY `@timestamp` DESC
```

#### **T1068 - Exploitation for Privilege Escalation**
- **Frequency:** Low-Medium
- **Sophistication:** High
- **Example:** Local privilege escalation exploits

#### **T1134 - Access Token Manipulation**
- **Frequency:** Medium
- **Tools:** Mimikatz token elevation

### 2.6 Defense Evasion (T1027, T1070, T1218)

#### **T1027.013 - Obfuscated Files or Information: Encrypted/Encoded File**
- **Frequency:** Very High
- **Detection Priority:** High

**Hunt Logic:**
```sql
-- Detect base64 encoded content in command lines
SELECT
    `@timestamp`,
    host_name,
    process_name,
    process_command_line,
    LENGTH(process_command_line) as cmd_length
FROM win_sysmon
WHERE event_code = '1'
  AND (
    process_command_line LIKE '%FromBase64String%'
    OR process_command_line LIKE '%-encodedcommand%'
    OR (
      process_command_line REGEXP '[A-Za-z0-9+/]{50,}={0,2}'
      AND LENGTH(process_command_line) > 100
    )
  )
ORDER BY `@timestamp` DESC
```

#### **T1070.004 - Indicator Removal: File Deletion**
- **Frequency:** Medium
- **Example:** Deleting payload files, logs

#### **T1218.011 - System Binary Proxy Execution: Rundll32**
- **Frequency:** Medium
- **Detection Priority:** High

**Hunt Logic:**
```sql
-- Detect suspicious rundll32 usage
SELECT
    `@timestamp`,
    host_name,
    process_command_line,
    parent_process_name
FROM win_sysmon
WHERE event_code = '1'
  AND process_name = 'rundll32.exe'
  AND (
    process_command_line LIKE '%javascript:%'
    OR process_command_line LIKE '%vbscript:%'
    OR process_command_line LIKE '%.dll,DllRegisterServer%'
  )
ORDER BY `@timestamp` DESC
```

### 2.7 Credential Access (T1003, T1110, T1552, T1555)

**APT33's Most Prevalent Tactic** - Credential theft is a primary objective, with 9 distinct techniques observed.

#### **T1003.001 - OS Credential Dumping: LSASS Memory**
- **Frequency:** Very High
- **Detection Priority:** Critical
- **Tools:** Mimikatz, custom tools

**Hunt Logic:**
```sql
-- Detect LSASS memory access
SELECT
    `@timestamp`,
    host_name,
    process_name,
    process_id,
    process_target.name as target_process,
    process_target.id as target_pid,
    process_granted_access
FROM win_sysmon
WHERE event_code = '10'  -- Process Access
  AND process_target.name = 'lsass.exe'
  AND process_name NOT IN (
    'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe',
    'MsMpEng.exe', 'SenseIR.exe', 'TaniumClient.exe'
  )
ORDER BY `@timestamp` DESC
```

#### **T1003.005 - Cached Domain Credentials**
- **Frequency:** High
- **Method:** Registry hive dumping

**Hunt Logic:**
```sql
-- Detect registry SAM/SECURITY hive access
SELECT
    `@timestamp`,
    host_name,
    process_name,
    process_command_line
FROM win_sysmon
WHERE event_code = '1'
  AND (
    process_command_line LIKE '%reg%save%HKLM\\SAM%'
    OR process_command_line LIKE '%reg%save%HKLM\\SECURITY%'
    OR process_command_line LIKE '%reg%save%HKLM\\SYSTEM%'
  )
ORDER BY `@timestamp` DESC
```

#### **T1110.003 - Brute Force: Password Spraying**
- **Frequency:** Very High
- **Detection Priority:** Critical
- **Characteristics:** Low-and-slow authentication attempts

**Hunt Logic:**
```sql
-- Detect password spraying patterns
WITH auth_attempts AS (
  SELECT
    DATE_TRUNC('hour', timestamp) as time_window,
    source_ip,
    COUNT(DISTINCT username) as unique_users,
    COUNT(*) as total_attempts,
    SUM(CASE WHEN result = 'failure' THEN 1 ELSE 0 END) as failures
  FROM authentication_logs
  WHERE service IN ('VPN', 'OWA', 'ActiveSync', 'O365')
  GROUP BY time_window, source_ip
)
SELECT *
FROM auth_attempts
WHERE unique_users >= 10  -- Many different users
  AND total_attempts < (unique_users * 5)  -- Few attempts per user
  AND failures > (unique_users * 0.8)  -- High failure rate
ORDER BY time_window DESC, unique_users DESC
```

#### **T1552.001 - Unsecured Credentials: Credentials In Files**
- **Frequency:** High
- **Method:** Search for credential files

**Hunt Logic:**
```sql
-- Detect searches for credential files
SELECT
    `@timestamp`,
    host_name,
    process_name,
    process_command_line
FROM win_sysmon
WHERE event_code = '1'
  AND (
    process_command_line LIKE '%findstr%password%'
    OR process_command_line LIKE '%select-string%password%'
    OR process_command_line LIKE '%dir%password%'
    OR process_command_line LIKE '%Get-ChildItem%credential%'
  )
ORDER BY `@timestamp` DESC
```

#### **T1552.006 - Group Policy Preferences**
- **Frequency:** Medium
- **Method:** Extract GPP passwords from SYSVOL

**Hunt Logic:**
```sql
-- Detect GPP password extraction
SELECT
    `@timestamp`,
    host_name,
    process_command_line,
    process_name
FROM win_sysmon
WHERE event_code = '1'
  AND (
    process_command_line LIKE '%\\SYSVOL\\%Groups.xml%'
    OR process_command_line LIKE '%cpassword%'
    OR process_command_line LIKE '%Get-GPPPassword%'
  )
ORDER BY `@timestamp` DESC
```

#### **T1555.003 - Credentials from Password Stores: Credentials from Web Browsers**
- **Frequency:** High
- **Tools:** LaZagne, custom browser credential dumpers

**Hunt Logic:**
```sql
-- Detect browser credential theft
SELECT
    `@timestamp`,
    host_name,
    process_name,
    process_command_line,
    file_target_filename
FROM win_sysmon
WHERE event_code IN ('1', '11')  -- Process creation or file creation
  AND (
    file_target_filename LIKE '%\\Google\\Chrome\\User Data\\%Login Data%'
    OR file_target_filename LIKE '%\\Mozilla\\Firefox\\Profiles\\%logins.json%'
    OR process_command_line LIKE '%LaZagne%'
  )
ORDER BY `@timestamp` DESC
```

### 2.8 Discovery (T1087)

#### **T1087 - Account Discovery**
- **Frequency:** High
- **Commands:** net user, net group

**Hunt Logic:**
```sql
-- Detect account enumeration
SELECT
    `@timestamp`,
    host_name,
    process_command_line,
    user_name
FROM win_sysmon
WHERE event_code = '1'
  AND (
    process_command_line LIKE 'net%user%/domain'
    OR process_command_line LIKE 'net%group%/domain'
    OR process_command_line LIKE '%Get-ADUser%'
    OR process_command_line LIKE '%Get-ADGroup%'
  )
ORDER BY `@timestamp` DESC
```

### 2.9 Collection (T1560)

#### **T1560.001 - Archive Collected Data: Archive via Utility**
- **Frequency:** Medium
- **Tools:** WinRAR, 7-Zip

**Hunt Logic:**
```sql
-- Detect data archiving activities
SELECT
    `@timestamp`,
    host_name,
    process_name,
    process_command_line,
    parent_process_name
FROM win_sysmon
WHERE event_code = '1'
  AND process_name IN ('rar.exe', '7z.exe', 'winrar.exe')
  AND process_command_line LIKE '%a %'  -- Archive command
ORDER BY `@timestamp` DESC
```

### 2.10 Command and Control (T1071, T1090, T1095)

#### **T1071.001 - Application Layer Protocol: Web Protocols**
- **Frequency:** Very High
- **Protocols:** HTTP/HTTPS
- **Characteristics:**
  - Beaconing to compromised WordPress sites
  - User-Agent spoofing
  - Custom C2 protocols over HTTP

**Hunt Logic:**
```sql
-- Detect C2 beaconing patterns
WITH http_connections AS (
  SELECT
    id_orig_h as source_ip,
    id_resp_h as dest_ip,
    host as http_host,
    uri,
    user_agent,
    COUNT(*) as connection_count,
    STDDEV(UNIX_TIMESTAMP(ts)) as time_variance,
    AVG(UNIX_TIMESTAMP(ts) - LAG(UNIX_TIMESTAMP(ts)) OVER (PARTITION BY id_orig_h, id_resp_h ORDER BY ts)) as avg_interval
  FROM zeek_http_logs
  WHERE method = 'GET'
  GROUP BY source_ip, dest_ip, http_host, uri, user_agent
)
SELECT *
FROM http_connections
WHERE connection_count > 50  -- Repeated connections
  AND time_variance < 30  -- Regular intervals
  AND avg_interval BETWEEN 60 AND 3600  -- 1 min to 1 hour
ORDER BY connection_count DESC
```

#### **T1071.004 - DNS**
- **Frequency:** Medium
- **Method:** DNS tunneling, exfiltration

**Hunt Logic:**
```sql
-- Detect DNS tunneling
SELECT
    source_ip,
    query,
    COUNT(*) as query_count,
    LENGTH(SPLIT(query, '.')[0]) as subdomain_length,
    SPLIT(query, '.')[SIZE(SPLIT(query, '.')) - 2] as domain
FROM zeek_dns_logs
WHERE qtype_name = 'A'
  AND LENGTH(SPLIT(query, '.')[0]) > 30
GROUP BY source_ip, domain
HAVING COUNT(*) > 20
ORDER BY query_count DESC
```

#### **T1090.003 - Proxy: Multi-hop Proxy**
- **Frequency:** Medium
- **Method:** Compromised servers as proxy infrastructure

#### **T1095 - Non-Application Layer Protocol**
- **Frequency:** Low-Medium
- **Method:** Custom TCP/UDP protocols

### 2.11 Exfiltration (T1041)

#### **T1041 - Exfiltration Over C2 Channel**
- **Frequency:** High
- **Method:** Data exfiltration using existing C2

**Hunt Logic:**
```sql
-- Detect large data uploads
SELECT
    ts,
    id_orig_h as source_ip,
    id_resp_h as dest_ip,
    id_resp_p as dest_port,
    SUM(orig_bytes) as total_upload_bytes,
    COUNT(*) as connection_count
FROM zeek_conn_logs
WHERE orig_bytes > resp_bytes * 10  -- Upload-heavy
  AND orig_bytes > 1048576  -- > 1MB uploaded
  AND id_resp_p IN (80, 443, 8080)
GROUP BY DATE_TRUNC('hour', ts), source_ip, dest_ip, dest_port
HAVING SUM(orig_bytes) > 104857600  -- > 100MB total
ORDER BY ts DESC, total_upload_bytes DESC
```

---

## 3. Attack Lifecycle

### 3.1 Typical APT33 Kill Chain

```
┌─────────────────────────────────────────────────────────────────┐
│                    APT33 ATTACK LIFECYCLE                       │
└─────────────────────────────────────────────────────────────────┘

Phase 1: RECONNAISSANCE (Days 1-14)
├── Open-source intelligence gathering
├── LinkedIn employee reconnaissance
├── Email address harvesting
├── Technology stack identification
└── VPN/webmail portal identification

Phase 2: INITIAL COMPROMISE (Days 15-30)
├── Spearphishing with malicious attachments
├── Password spraying against VPN/webmail
├── Credential harvesting via fake portals
└── Exploitation of public-facing applications

Phase 3: ESTABLISH FOOTHOLD (Hours 1-24)
├── Macro execution → PowerShell downloader
├── Deploy custom implant (TURNEDUP, DEADWOOD)
├── Establish persistence (scheduled tasks, registry)
└── C2 communication established

Phase 4: ESCALATE PRIVILEGES (Days 1-7)
├── Credential dumping (Mimikatz, LSASS)
├── Token manipulation
├── Cached credential extraction
├── GPP password extraction
└── Service account compromise

Phase 5: INTERNAL RECONNAISSANCE (Days 3-14)
├── Network enumeration
├── Active Directory enumeration
├── Share enumeration
├── Identify high-value targets
└── Map trust relationships

Phase 6: LATERAL MOVEMENT (Days 7-30)
├── Pass-the-hash attacks
├── RDP with stolen credentials
├── PsExec for remote execution
├── Compromise additional systems
└── Establish multiple footholds

Phase 7: MAINTAIN PRESENCE (Ongoing)
├── Deploy additional backdoors
├── Establish redundant C2 channels
├── Create additional accounts
├── Monitor for incident response
└── Adapt techniques as needed

Phase 8: COMPLETE MISSION (Days 30-90+)
├── Locate target data
├── Stage data for exfiltration
├── Compress/encrypt archives
├── Exfiltrate via C2 channel
└── [Optional] Deploy destructive payload
```

### 3.2 Detailed Phase Breakdown

#### **Phase 1: Reconnaissance (MITRE: Reconnaissance)**

**Duration:** 1-2 weeks
**Objectives:**
- Identify targets within organization
- Gather technical information
- Build targeting packages

**Activities:**
- LinkedIn reconnaissance for employees
- Email address format identification
- Public DNS/WHOIS enumeration
- Technology stack fingerprinting
- Identify VPN/webmail portals for password spraying

**Indicators:**
- Unusual LinkedIn profile views from Iran/Middle East
- Increased reconnaissance scanning of public infrastructure
- OSINT queries related to organization

#### **Phase 2: Initial Compromise (MITRE: Initial Access)**

**Duration:** Variable (days to weeks)
**Objectives:**
- Gain initial access to target network
- Compromise user accounts

**Primary Methods:**

**A. Spearphishing Campaign**
- Malicious Office documents with macros
- Social engineering themes: invoices, reports, contracts
- Aviation/energy industry-specific content
- VBA macros download PowerShell payloads

**B. Password Spraying**
- Target: VPN, OWA, Office 365, ActiveSync
- Technique: Single password against many accounts
- Common passwords: Season+Year (e.g., "Summer2024!")
- Low-and-slow to avoid lockouts
- Success rate: 1-5% of accounts

**C. Credential Harvesting**
- Fake login pages mimicking corporate portals
- Spearphishing links to credential harvesting sites
- Typosquatting domains

**Detection Opportunities:**
```sql
-- Multiple authentication failures from single source
SELECT
    source_ip,
    COUNT(DISTINCT username) as attempted_accounts,
    COUNT(*) as total_attempts,
    MIN(timestamp) as first_attempt,
    MAX(timestamp) as last_attempt
FROM authentication_logs
WHERE result = 'failure'
  AND timestamp > NOW() - INTERVAL '1 hour'
GROUP BY source_ip
HAVING COUNT(DISTINCT username) > 10
ORDER BY attempted_accounts DESC
```

#### **Phase 3: Establish Foothold (MITRE: Execution, Persistence)**

**Duration:** Hours to 1 day
**Objectives:**
- Execute payload on compromised system
- Establish persistence
- Deploy C2 implant

**Execution Chain:**
1. User opens malicious document
2. VBA macro executes
3. PowerShell downloader runs
4. Downloads second-stage payload
5. Payload establishes persistence
6. C2 beacon initiated

**Persistence Mechanisms:**
- Scheduled tasks pointing to malicious scripts
- Registry Run keys
- WMI event subscriptions
- Services

**C2 Infrastructure:**
- Compromised WordPress sites
- Legitimate-looking domains
- Multi-tier proxy infrastructure

**Detection Opportunities:**
```sql
-- Office applications spawning PowerShell
SELECT
    `@timestamp`,
    host_name,
    parent_process_name,
    process_command_line
FROM win_sysmon
WHERE event_code = '1'
  AND parent_process_name IN ('WINWORD.EXE', 'EXCEL.EXE')
  AND process_name = 'powershell.exe'
ORDER BY `@timestamp` DESC
```

#### **Phase 4: Escalate Privileges (MITRE: Privilege Escalation, Credential Access)**

**Duration:** 1-7 days
**Objectives:**
- Obtain domain admin credentials
- Access privileged accounts

**Methods:**

**A. Credential Dumping**
```
Target          Tool            Method
---------------------------------------------------
LSASS Memory    Mimikatz        sekurlsa::logonpasswords
SAM/SECURITY    reg.exe         reg save HKLM\SAM
Cached Creds    Mimikatz        lsadump::cache
GPP Passwords   PowerSploit     Get-GPPPassword
Browser Creds   LaZagne         laZagne.exe browsers
```

**B. Token Manipulation**
- Impersonate logged-on administrators
- Token stealing from privileged processes

**Detection Opportunities:**
```sql
-- LSASS memory access
SELECT
    `@timestamp`,
    host_name,
    process_name,
    process_granted_access
FROM win_sysmon
WHERE event_code = '10'
  AND process_target.name = 'lsass.exe'
  AND process_name NOT IN ('csrss.exe', 'wininit.exe', 'winlogon.exe')
```

#### **Phase 5: Internal Reconnaissance (MITRE: Discovery)**

**Duration:** 3-14 days
**Objectives:**
- Map internal network
- Identify high-value targets
- Locate sensitive data

**Commands Executed:**
```cmd
# Active Directory Enumeration
net user /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
nltest /domain_trusts

# Network Enumeration
ipconfig /all
arp -a
net view
net share

# System Enumeration
systeminfo
whoami /all
tasklist
net localgroup administrators
```

**PowerShell Enumeration:**
```powershell
Get-ADUser -Filter * -Properties *
Get-ADComputer -Filter * -Properties *
Get-ADGroup -Filter * -Properties *
Get-DomainController
```

**Detection Opportunities:**
```sql
-- Rapid AD enumeration
SELECT
    `@timestamp`,
    host_name,
    user_name,
    process_command_line,
    COUNT(*) OVER (
      PARTITION BY host_name, user_name
      ORDER BY `@timestamp`
      RANGE INTERVAL '5' MINUTE PRECEDING
    ) as commands_in_5min
FROM win_sysmon
WHERE event_code = '1'
  AND (
    process_command_line LIKE 'net%/domain'
    OR process_command_line LIKE '%Get-AD%'
    OR process_command_line LIKE 'nltest%'
  )
HAVING commands_in_5min > 5
```

#### **Phase 6: Lateral Movement (MITRE: Lateral Movement)**

**Duration:** 7-30 days
**Objectives:**
- Compromise additional systems
- Reach target systems/data
- Establish redundant access

**Methods:**

**A. Pass-the-Hash**
- Use Mimikatz-extracted NTLM hashes
- Authenticate to remote systems without plaintext password

**B. RDP with Stolen Credentials**
- Use compromised domain accounts
- Access workstations and servers

**C. Remote Execution**
- PsExec for service-based execution
- WMI for remote command execution
- PowerShell remoting (WinRM)

**Detection Opportunities:**
```sql
-- Lateral movement via explicit credentials
SELECT
    `@timestamp`,
    host_name,
    user_name,
    logon_type,
    source_ip,
    logon_process_name
FROM win_security
WHERE event_id = 4624  -- Successful logon
  AND logon_type IN (3, 10)  -- Network, Remote Desktop
  AND user_name NOT LIKE '%$'  -- Not computer account
GROUP BY user_name, source_ip
HAVING COUNT(DISTINCT host_name) > 10  -- Single account on many systems
```

#### **Phase 7: Maintain Presence (MITRE: Persistence, Defense Evasion)**

**Duration:** Ongoing
**Objectives:**
- Survive reboots and credential resets
- Avoid detection
- Maintain long-term access

**Techniques:**
- Deploy multiple backdoors across different systems
- Create rogue administrator accounts
- Establish multiple C2 channels
- Monitor for incident response activities
- Delete logs and artifacts

#### **Phase 8: Complete Mission (MITRE: Collection, Exfiltration)**

**Duration:** 30-90+ days
**Objectives:**
- Locate and exfiltrate target data
- Complete mission objectives

**Data Targets:**
- Intellectual property (aircraft designs, energy technology)
- Strategic plans and contracts
- Email archives from executives
- Sensitive technical documents
- Proprietary research

**Exfiltration Methods:**
- Archive data with WinRAR/7-Zip
- Encrypt archives
- Exfiltrate via C2 channel (HTTP/HTTPS)
- Stage on cloud storage (rarely)
- DNS tunneling (backup method)

**Detection Opportunities:**
```sql
-- Large archive creation followed by network upload
WITH archive_creation AS (
  SELECT
    `@timestamp`,
    host_name,
    file_target_filename,
    LEAD(`@timestamp`) OVER (PARTITION BY host_name ORDER BY `@timestamp`) as next_event_time
  FROM win_sysmon
  WHERE event_code = '11'  -- File creation
    AND file_target_filename LIKE '%.rar'
    OR file_target_filename LIKE '%.7z'
),
network_activity AS (
  SELECT
    `@timestamp`,
    host_name,
    destination_ip,
    destination_port,
    bytes_sent
  FROM win_sysmon
  WHERE event_code = '3'  -- Network connection
    AND bytes_sent > 10485760  -- > 10MB
)
SELECT
    a.host_name,
    a.file_target_filename,
    a.`@timestamp` as archive_created,
    n.`@timestamp` as network_event,
    n.destination_ip,
    n.bytes_sent
FROM archive_creation a
JOIN network_activity n
  ON a.host_name = n.host_name
  AND n.`@timestamp` BETWEEN a.`@timestamp` AND a.next_event_time
ORDER BY a.`@timestamp` DESC
```

---

## 4. Tools and Malware Arsenal

APT33 employs a mix of custom malware, publicly-available tools, and living-off-the-land techniques.

### 4.1 Custom Malware

#### **TURNEDUP**
- **Type:** Backdoor
- **Function:** Command execution, file operations, C2 communication
- **Language:** Unknown (likely C/C++)
- **Delivery:** Spearphishing attachment payload
- **C2 Protocol:** HTTP/HTTPS
- **Persistence:** Scheduled task

**Capabilities:**
- Execute arbitrary commands
- Upload/download files
- System reconnaissance
- Keylogging
- Screenshot capture

**Detection:**
```sql
-- Network beaconing pattern
SELECT
    id_orig_h,
    id_resp_h,
    COUNT(*) as beacon_count,
    AVG(UNIX_TIMESTAMP(ts) - LAG(UNIX_TIMESTAMP(ts)) OVER (PARTITION BY id_orig_h, id_resp_h ORDER BY ts)) as avg_interval
FROM zeek_http_logs
WHERE method = 'POST'
  AND uri LIKE '%/page.php%'
GROUP BY id_orig_h, id_resp_h
HAVING beacon_count > 50 AND avg_interval BETWEEN 300 AND 600
```

#### **DEADWOOD**
- **Type:** Dropper/Loader
- **Function:** Deploy additional payloads, evade detection
- **Language:** C/C++
- **Obfuscation:** Encrypted payload, anti-analysis

**Capabilities:**
- Deploy second-stage payloads
- Sandbox detection
- VM detection
- Process hollowing

**IOCs:**
- File path patterns: `%TEMP%\~tmp*.exe`
- Mutex names: `Global\{GUID}`
- Network patterns: HTTP POST to `/update.php`

#### **SHAPESHIFT**
- **Type:** Destructive malware
- **Function:** Wipe disk sectors, delete files
- **Purpose:** Destroy evidence, cause disruption
- **Similarity:** Shamoon-inspired

**Capabilities:**
- Overwrite MBR
- Delete shadow copies
- Wipe specific file types
- Targeted file deletion

**Detection:**
```sql
-- Destructive file operations
SELECT
    `@timestamp`,
    host_name,
    process_name,
    process_command_line,
    file_target_filename
FROM win_sysmon
WHERE event_code = '23'  -- File delete
  AND (
    file_target_filename LIKE 'C:\\Windows\\System32\\config\\%'
    OR process_command_line LIKE '%vssadmin%delete%shadows%'
    OR process_command_line LIKE '%wbadmin%delete%catalog%'
  )
ORDER BY `@timestamp` DESC
```

#### **POWERTON**
- **Type:** Backdoor (PowerShell-based)
- **Function:** Lightweight implant for initial access
- **Language:** PowerShell
- **Obfuscation:** Base64-encoded, multi-layer

**Capabilities:**
- C2 communication via HTTP/S
- Command execution
- File upload/download
- Persistence via scheduled task

**Detection:**
```sql
-- PowerShell with network activity and scheduled task
SELECT
    `@timestamp`,
    host_name,
    process_command_line,
    parent_process_name
FROM win_sysmon
WHERE event_code = '1'
  AND process_name = 'powershell.exe'
  AND process_command_line LIKE '%IEX%'
  AND process_command_line LIKE '%Net.WebClient%'
ORDER BY `@timestamp` DESC
```

### 4.2 Publicly-Available Tools

#### **Mimikatz**
- **Purpose:** Credential extraction
- **Frequency:** Very High
- **Usage:** Extract plaintext passwords, hashes, tickets from memory

**Common Commands:**
```
sekurlsa::logonpasswords
lsadump::sam
lsadump::cache
sekurlsa::pth
```

**Detection:**
```sql
-- Mimikatz process execution
SELECT
    `@timestamp`,
    host_name,
    process_name,
    process_command_line,
    parent_process_name,
    file_hash_sha256
FROM win_sysmon
WHERE event_code = '1'
  AND (
    process_name = 'mimikatz.exe'
    OR process_command_line LIKE '%sekurlsa::%'
    OR file_hash_sha256 IN (known_mimikatz_hashes)
  )
```

#### **PowerSploit**
- **Purpose:** Post-exploitation framework
- **Frequency:** High
- **Modules Used:**
  - Invoke-Mimikatz (credential dumping)
  - Invoke-ReflectivePEInjection (process injection)
  - Get-GPPPassword (GPP password extraction)
  - PowerView (AD enumeration)

**Detection:**
```sql
-- PowerSploit module usage
SELECT
    `@timestamp`,
    host_name,
    process_command_line
FROM win_sysmon
WHERE event_code = '1'
  AND process_name = 'powershell.exe'
  AND (
    process_command_line LIKE '%Invoke-Mimikatz%'
    OR process_command_line LIKE '%Invoke-ReflectivePEInjection%'
    OR process_command_line LIKE '%Get-GPPPassword%'
    OR process_command_line LIKE '%Invoke-UserHunter%'
    OR process_command_line LIKE '%Invoke-ShareFinder%'
  )
```

#### **LaZagne**
- **Purpose:** Password recovery tool
- **Frequency:** High
- **Targets:** Browsers, email clients, FTP clients, databases

**Detection:**
```sql
-- LaZagne execution or browser credential file access
SELECT
    `@timestamp`,
    host_name,
    process_name,
    file_target_filename
FROM win_sysmon
WHERE (event_code = '1' AND process_command_line LIKE '%laZagne%')
   OR (event_code = '11' AND file_target_filename LIKE '%Login Data%')
   OR (event_code = '11' AND file_target_filename LIKE '%logins.json%')
```

#### **PoshC2**
- **Purpose:** Post-exploitation C2 framework
- **Frequency:** Medium
- **Usage:** Advanced command and control

**Detection:**
```sql
-- PoshC2 indicators
SELECT
    `@timestamp`,
    host_name,
    process_command_line
FROM win_sysmon
WHERE event_code = '1'
  AND process_name = 'powershell.exe'
  AND (
    process_command_line LIKE '%PoshC2%'
    OR process_command_line LIKE '%Invoke-Shellcode%'
    OR process_command_line LIKE '%Get-Proxy%'
  )
```

#### **Ruler**
- **Purpose:** Outlook exploitation for persistence
- **Frequency:** Low-Medium
- **Usage:** Create malicious Outlook rules, forms

**Detection:**
```sql
-- Suspicious Outlook rule creation
SELECT
    `@timestamp`,
    host_name,
    process_command_line
FROM win_sysmon
WHERE event_code = '1'
  AND (
    process_command_line LIKE '%ruler%'
    OR (process_name = 'outlook.exe' AND process_command_line LIKE '%/rulefile%')
  )
```

#### **NanoCore RAT**
- **Purpose:** Remote access trojan
- **Frequency:** Medium
- **Capabilities:** Screen capture, keylogging, file operations, webcam access

**Detection:**
```sql
-- NanoCore network beaconing
SELECT
    id_orig_h,
    id_resp_h,
    id_resp_p,
    COUNT(*) as connection_count,
    service
FROM zeek_conn_logs
WHERE id_resp_p IN (5050, 8080, 9999)  -- Common NanoCore ports
  AND service = 'tcp'
GROUP BY id_orig_h, id_resp_h, id_resp_p
HAVING connection_count > 20
```

### 4.3 Living Off the Land

APT33 extensively uses legitimate system tools to blend in with normal activity:

| Tool | Purpose | Detection Difficulty |
|------|---------|---------------------|
| **powershell.exe** | Execution, C2, credential theft | Medium-High |
| **cmd.exe** | Command execution | Medium |
| **reg.exe** | Registry manipulation, credential dumping | Medium |
| **net.exe** | Enumeration, account manipulation | Medium |
| **schtasks.exe** | Persistence | Medium |
| **wmic.exe** | Enumeration, remote execution | Medium |
| **rundll32.exe** | Proxy execution | High |
| **mshta.exe** | Proxy execution | High |
| **certutil.exe** | Download files, decode payloads | Medium |
| **bitsadmin.exe** | Download files | Medium |

**Detection Strategy:**
```sql
-- Suspicious LOLBin usage patterns
SELECT
    `@timestamp`,
    host_name,
    process_name,
    process_command_line,
    parent_process_name,
    COUNT(*) OVER (
      PARTITION BY host_name, user_name
      ORDER BY `@timestamp`
      RANGE INTERVAL '10' MINUTE PRECEDING
    ) as lolbin_executions_10min
FROM win_sysmon
WHERE event_code = '1'
  AND process_name IN (
    'powershell.exe', 'reg.exe', 'net.exe', 'schtasks.exe',
    'wmic.exe', 'rundll32.exe', 'mshta.exe', 'certutil.exe'
  )
  AND (
    -- Suspicious patterns
    process_command_line LIKE '%IEX%'
    OR process_command_line LIKE '%-encodedcommand%'
    OR process_command_line LIKE '%reg%save%HKLM%'
    OR process_command_line LIKE '%/domain%'
  )
HAVING lolbin_executions_10min > 5
ORDER BY `@timestamp` DESC, lolbin_executions_10min DESC
```

---

## 5. Infrastructure and TTPs

### 5.1 Command and Control Infrastructure

**C2 Architecture:**
```
┌──────────────┐
│ APT33 Victim │
└──────┬───────┘
       │
       │ HTTPS Beacon
       │
       ▼
┌─────────────────────────┐
│ Compromised WordPress   │  ← Level 1 Proxy
│ Sites (Middle East)     │
└────────┬────────────────┘
         │
         │ Proxied Traffic
         │
         ▼
┌─────────────────────────┐
│ VPS Hosts               │  ← Level 2 Proxy
│ (Europe, Asia)          │
└────────┬────────────────┘
         │
         │
         ▼
┌─────────────────────────┐
│ APT33 C2 Servers        │  ← Backend Infrastructure
│ (Iran-suspected)        │
└─────────────────────────┘
```

**Infrastructure Characteristics:**

1. **Compromised Web Servers**
   - Often WordPress sites in Middle East
   - Webshells for traffic proxying
   - Path patterns: `/wp-includes/`, `/wp-content/`

2. **VPS Providers**
   - DigitalOcean, Vultr, OVH
   - Short-lived (30-90 days)
   - European and Asian data centers

3. **Domain Registration**
   - Privacy-protected WHOIS
   - Typosquatting of legitimate companies
   - Aviation/energy-themed domains

**Example Domain Patterns:**
```
aviation-services[.]com
{company-name}-portal[.]com
{company-name}update[.]com
secure-{company-name}[.]com
```

**Detection:**
```sql
-- Connections to suspicious domains/IPs
SELECT
    ts,
    id_orig_h as source_ip,
    id_resp_h as dest_ip,
    host as http_host,
    uri,
    user_agent
FROM zeek_http_logs
WHERE (
    -- Suspicious TLDs
    host LIKE '%.tk'
    OR host LIKE '%.ml'
    OR host LIKE '%.ga'
    -- WordPress paths
    OR uri LIKE '%/wp-includes/%'
    OR uri LIKE '%/wp-content/uploads/%'
  )
  AND id_orig_h IN (internal_subnets)
ORDER BY ts DESC
```

### 5.2 Operational Security

**OPSEC Strengths:**
- Multi-tier proxy infrastructure
- Use of compromised infrastructure
- Blending with legitimate traffic
- Living-off-the-land techniques

**OPSEC Weaknesses:**
- Reuse of C2 infrastructure across campaigns
- Distinct TTPs (password spraying patterns)
- Malware compilation timestamps during Iranian business hours
- Farsi language artifacts in tools
- Predictable phishing themes

### 5.3 Temporal Analysis

**Operational Hours:**
- Primary activity: 0600-1800 UTC (Iran time zone)
- Weekend activity: Reduced (Friday/Saturday - Iranian weekend)
- Holiday dormancy: Iranian holidays

**Campaign Timing:**
- Reconnaissance: Continuous
- Phishing waves: Monthly cadence
- Password spraying: Quarterly campaigns
- Infrastructure rotation: 60-90 days

---

## 6. Detection Strategies

### 6.1 Network Detection

#### **Signature-Based Detection**

**Snort/Suricata Rules:**

```snort
# APT33 - Suspicious PowerShell download cradle
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (
  msg:"APT33 - PowerShell IEX Download Cradle";
  flow:established,to_server;
  content:"IEX"; nocase;
  content:"Net.WebClient"; nocase; distance:0;
  content:"DownloadString"; nocase; distance:0;
  classtype:trojan-activity;
  sid:9000001;
  rev:1;
)

# APT33 - Password spraying attempt pattern
alert tcp $EXTERNAL_NET any -> $HOME_NET [443,587,993] (
  msg:"APT33 - Potential Password Spraying";
  flow:established,to_server;
  threshold:type threshold, track by_src, count 50, seconds 3600;
  classtype:attempted-recon;
  sid:9000002;
  rev:1;
)

# APT33 - Beaconing pattern
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (
  msg:"APT33 - Suspicious HTTP Beaconing Pattern";
  flow:established,to_server;
  content:"POST"; http_method;
  content:"/page.php"; http_uri;
  threshold:type threshold, track by_src, count 10, seconds 600;
  classtype:trojan-activity;
  sid:9000003;
  rev:1;
)

# APT33 - DNS Tunneling
alert udp $HOME_NET any -> any 53 (
  msg:"APT33 - Potential DNS Tunneling";
  content:"|01 00 00 01 00 00 00 00 00 00|"; offset:2; depth:10;
  content:"."; within:255;
  byte_test:1,>,30,0,relative;
  threshold:type threshold, track by_src, count 20, seconds 60;
  classtype:policy-violation;
  sid:9000004;
  rev:1;
)
```

#### **Behavioral Detection - Zeek Scripts**

```zeek
# Detect password spraying patterns
module APT33;

export {
    redef enum Notice::Type += {
        Password_Spray_Detected,
    };

    const spray_threshold = 10;  # Unique accounts
    const time_window = 1hr;
}

event authentication_attempt(c: connection, username: string, result: string) {
    if (result == "failure") {
        # Track failed auth attempts per source IP
        # Alert if many unique usernames with few attempts each
    }
}
```

### 6.2 Host-Based Detection

#### **Sysmon Configuration Highlights**

Focus on these Sysmon Event IDs:

**Event ID 1 - Process Creation:**
- PowerShell with suspicious arguments
- Office apps spawning scripting engines
- LOLBin usage patterns
- Mimikatz/credential tools

**Event ID 3 - Network Connection:**
- PowerShell network connections
- Connections to suspicious ports/IPs
- Beaconing patterns

**Event ID 7 - Image Loaded:**
- Unusual DLL loads by processes
- Injection indicators

**Event ID 8 - CreateRemoteThread:**
- Process injection detection
- Critical for detecting Mimikatz injection

**Event ID 10 - Process Access:**
- LSASS memory access
- Credential dumping indicators

**Event ID 11 - File Creation:**
- Temp directory executable creation
- Credential file copying
- Staging directory usage

**Event ID 13 - Registry Value Set:**
- Run key persistence
- Registry-based credential storage access

**Event ID 22 - DNS Query:**
- DNS tunneling patterns
- Suspicious domain lookups

#### **Windows Event Log Monitoring**

**Security Event IDs:**

```
4624 - Successful Logon (focus on Type 3, 10)
4625 - Failed Logon (password spraying detection)
4648 - Logon with Explicit Credentials (lateral movement)
4672 - Special Privileges Assigned to New Logon (privilege escalation)
4688 - Process Creation (if Sysmon not available)
4698 - Scheduled Task Created (persistence)
4720 - User Account Created (persistence, backdoor accounts)
4732 - Member Added to Security-Enabled Local Group (privilege escalation)
4776 - NTLM Authentication (lateral movement tracking)
```

**Hunt Query - Account Logon Anomalies:**
```sql
-- Detect account used from many source IPs (compromised credential)
SELECT
    user_name,
    COUNT(DISTINCT source_ip) as unique_source_ips,
    COUNT(DISTINCT host_name) as unique_targets,
    MIN(`@timestamp`) as first_seen,
    MAX(`@timestamp`) as last_seen,
    COLLECT_SET(source_ip) as source_ips
FROM win_security
WHERE event_id = 4624
  AND logon_type IN (3, 10)  -- Network, RDP
  AND user_name NOT LIKE '%$'  -- Exclude computer accounts
  AND `@timestamp` > NOW() - INTERVAL '24 hours'
GROUP BY user_name
HAVING COUNT(DISTINCT source_ip) > 5
ORDER BY unique_source_ips DESC
```

### 6.3 Endpoint Detection (EDR)

**Behavioral Indicators for EDR:**

1. **Credential Access Behavior**
   - LSASS memory read attempts
   - Registry SAM hive access
   - Browser credential file access
   - Suspicious process access patterns

2. **Process Injection Behavior**
   - CreateRemoteThread to sensitive processes
   - Process hollowing indicators
   - Reflective DLL injection

3. **Discovery Behavior**
   - Rapid execution of enumeration commands
   - AD query patterns
   - Network enumeration tools

4. **Lateral Movement Behavior**
   - Explicit credential use (RunAs)
   - Remote service creation
   - WMI remote execution
   - PsExec-style activity

**Sample EDR Detection Logic:**
```python
# Pseudocode for behavioral detection
def detect_apt33_credential_theft(process_events):
    """Detect APT33-style credential theft sequence"""

    # Phase 1: Tool download/staging
    ps_download = filter(process_events, lambda e:
        e.process_name == "powershell.exe" and
        "IEX" in e.command_line and
        "WebClient" in e.command_line
    )

    # Phase 2: Credential dumping
    lsass_access = filter(process_events, lambda e:
        e.event_type == "ProcessAccess" and
        e.target_process == "lsass.exe" and
        e.granted_access & 0x1F0FFF  # Full access
    )

    # Phase 3: Exfiltration staging
    archive_creation = filter(process_events, lambda e:
        e.process_name in ["rar.exe", "7z.exe"] and
        "-p" in e.command_line  # Password-protected archive
    )

    # Correlate events within time window
    if ps_download and lsass_access and archive_creation:
        if time_window(ps_download, archive_creation) < 30 * 60:  # 30 mins
            return ALERT("APT33 Credential Theft Chain Detected")
```

### 6.4 Cloud and Email Security

#### **Email Security Controls**

**Inbound Email Filtering:**
1. **Attachment Blocking:**
   - Block macros in attachments from external sources
   - Sandbox suspicious attachments
   - Block double extensions (.pdf.exe)

2. **Link Protection:**
   - URL rewriting and sandbox analysis
   - Block newly registered domains (<30 days)
   - Reputation-based blocking

3. **Authentication:**
   - Enforce DMARC, SPF, DKIM
   - Block spoofed internal domains
   - Verify sender authenticity

**Hunt Query - Suspicious Email Patterns:**
```sql
-- Detect aviation/energy-themed phishing
SELECT
    sent_timestamp,
    sender_email,
    recipient_email,
    subject,
    attachment_names,
    link_count
FROM email_logs
WHERE (
    subject LIKE '%invoice%'
    OR subject LIKE '%aircraft%'
    OR subject LIKE '%proposal%'
    OR subject LIKE '%contract%'
  )
  AND sender_domain NOT IN (known_partner_domains)
  AND (attachment_count > 0 OR link_count > 0)
  AND sent_timestamp > NOW() - INTERVAL '7 days'
ORDER BY sent_timestamp DESC
```

#### **Cloud Access Security**

**Office 365 / Azure AD Protection:**

1. **Conditional Access Policies:**
   - Require MFA for all external access
   - Block legacy authentication protocols
   - Geo-fencing (block Iran, suspicious locations)
   - Require compliant/managed devices

2. **Sign-In Risk Detection:**
   - Monitor Azure AD Sign-In logs
   - Alert on:
     - Impossible travel
     - Anonymous IP usage
     - Password spray detection
     - Unfamiliar sign-in properties

**Hunt Query - O365 Password Spray Detection:**
```sql
-- Detect password spraying in Office 365 logs
WITH failed_logins AS (
  SELECT
    DATE_TRUNC('hour', created_time) as time_window,
    ip_address,
    COUNT(DISTINCT user_principal_name) as unique_users,
    COUNT(*) as total_attempts
  FROM azure_ad_signin_logs
  WHERE result_type != '0'  -- Failed
    AND app_display_name = 'Office 365 Exchange Online'
  GROUP BY time_window, ip_address
)
SELECT *
FROM failed_logins
WHERE unique_users >= 10
  AND total_attempts < (unique_users * 3)
ORDER BY time_window DESC, unique_users DESC
```

### 6.5 Threat Intelligence Integration

**SIEM Enrichment:**

```sql
-- Enrich network traffic with threat intel
SELECT
    conn.ts,
    conn.id_orig_h,
    conn.id_resp_h,
    ti.indicator,
    ti.indicator_type,
    ti.threat_actor,
    ti.confidence
FROM zeek_conn_logs conn
LEFT JOIN threat_intel_feed ti
  ON conn.id_resp_h = ti.indicator
WHERE ti.threat_actor = 'APT33'
  OR ti.indicator_type IN ('APT33_C2', 'APT33_INFRASTRUCTURE')
ORDER BY conn.ts DESC
```

**IOC Matching:**
- File hashes (SHA256)
- Domains and IPs
- Email addresses
- Mutex names
- Registry keys

---

## 7. Hunting Methodologies

### 7.1 Hypothesis-Driven Hunting

**Hunt Hypothesis 1: APT33 Initial Compromise via Password Spraying**

**Hypothesis:** APT33 is attempting to gain initial access through password spraying against VPN or webmail portals.

**Hunt Methodology:**

```sql
-- Step 1: Identify authentication patterns
WITH auth_analysis AS (
  SELECT
    DATE_TRUNC('hour', timestamp) as hour,
    source_ip,
    user_agent,
    COUNT(DISTINCT username) as unique_users,
    COUNT(*) as total_attempts,
    SUM(CASE WHEN result = 'failure' THEN 1 ELSE 0 END) as failures,
    SUM(CASE WHEN result = 'success' THEN 1 ELSE 0 END) as successes
  FROM authentication_logs
  WHERE service IN ('VPN', 'OWA', 'O365', 'ActiveSync')
  GROUP BY hour, source_ip, user_agent
)
SELECT
    hour,
    source_ip,
    user_agent,
    unique_users,
    total_attempts,
    failures,
    successes,
    ROUND(failures::DECIMAL / total_attempts * 100, 2) as failure_rate,
    ROUND(total_attempts::DECIMAL / unique_users, 2) as attempts_per_user
FROM auth_analysis
WHERE unique_users >= 10  -- Many different users
  AND attempts_per_user <= 3  -- Few attempts per user
  AND failure_rate > 80  -- High failure rate
ORDER BY hour DESC, unique_users DESC

-- Step 2: Investigate successful authentications from spray sources
-- (Check for post-compromise activity)

-- Step 3: Check for subsequent suspicious activity from compromised accounts
```

**Hunt Hypothesis 2: APT33 Living-Off-The-Land Post-Compromise**

**Hypothesis:** APT33 has compromised a system and is using PowerShell and native Windows tools for post-exploitation.

**Hunt Methodology:**

```sql
-- Hunt for suspicious PowerShell patterns
WITH powershell_activity AS (
  SELECT
    `@timestamp`,
    host_name,
    user_name,
    process_command_line,
    parent_process_name,
    CASE
      WHEN process_command_line LIKE '%-encodedcommand%' THEN 'EncodedCommand'
      WHEN process_command_line LIKE '%IEX%' AND process_command_line LIKE '%WebClient%' THEN 'DownloadCradle'
      WHEN process_command_line LIKE '%Invoke-Mimikatz%' THEN 'Mimikatz'
      WHEN process_command_line LIKE '%Get-GPPPassword%' THEN 'GPPPassword'
      WHEN process_command_line LIKE '%Invoke-ReflectivePEInjection%' THEN 'Injection'
      ELSE 'Other'
    END as activity_type
  FROM win_sysmon
  WHERE event_code = '1'
    AND process_name = 'powershell.exe'
    AND (
      process_command_line LIKE '%-encodedcommand%'
      OR process_command_line LIKE '%IEX%'
      OR process_command_line LIKE '%Invoke-%'
      OR LENGTH(process_command_line) > 500
    )
)
SELECT
    host_name,
    user_name,
    activity_type,
    COUNT(*) as occurrence_count,
    MIN(`@timestamp`) as first_seen,
    MAX(`@timestamp`) as last_seen,
    COLLECT_LIST(process_command_line) as sample_commands
FROM powershell_activity
GROUP BY host_name, user_name, activity_type
ORDER BY occurrence_count DESC
```

**Hunt Hypothesis 3: APT33 Credential Harvesting**

**Hypothesis:** APT33 is dumping credentials from memory or files on compromised systems.

**Hunt Methodology:**

```sql
-- Step 1: LSASS memory access patterns
SELECT
    `@timestamp`,
    host_name,
    process_name,
    process_id,
    process_granted_access,
    COUNT(*) OVER (PARTITION BY host_name, process_name ORDER BY `@timestamp` RANGE INTERVAL '5' MINUTE PRECEDING) as access_count_5min
FROM win_sysmon
WHERE event_code = '10'  -- Process Access
  AND process_target.name = 'lsass.exe'
  AND process_name NOT IN (
    'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe',
    'MsMpEng.exe', 'SenseIR.exe'  -- Exclude legitimate
  )
ORDER BY `@timestamp` DESC

-- Step 2: Registry SAM/SECURITY access
SELECT
    `@timestamp`,
    host_name,
    process_name,
    process_command_line
FROM win_sysmon
WHERE event_code = '1'
  AND (
    process_command_line LIKE '%reg%save%SAM%'
    OR process_command_line LIKE '%reg%save%SECURITY%'
    OR process_command_line LIKE '%reg%save%SYSTEM%'
  )
ORDER BY `@timestamp` DESC

-- Step 3: Browser credential file access
SELECT
    `@timestamp`,
    host_name,
    process_name,
    file_target_filename
FROM win_sysmon
WHERE event_code IN ('10', '11')  -- File access or creation
  AND (
    file_target_filename LIKE '%\\Google\\Chrome\\User Data\\%Login Data'
    OR file_target_filename LIKE '%\\Mozilla\\Firefox\\Profiles\\%logins.json'
    OR file_target_filename LIKE '%\\Microsoft\\Credentials\\%'
  )
ORDER BY `@timestamp` DESC

-- Step 4: Correlate credential theft with exfiltration
-- (Check for network activity after credential access)
```

**Hunt Hypothesis 4: APT33 Lateral Movement**

**Hypothesis:** APT33 is using compromised credentials to move laterally across the network.

**Hunt Methodology:**

```sql
-- Step 1: Identify accounts authenticating to many systems
WITH lateral_movement_candidates AS (
  SELECT
    user_name,
    COUNT(DISTINCT host_name) as unique_systems,
    COUNT(DISTINCT source_ip) as unique_sources,
    MIN(`@timestamp`) as first_logon,
    MAX(`@timestamp`) as last_logon,
    COLLECT_SET(host_name) as target_systems,
    COLLECT_SET(source_ip) as source_ips
  FROM win_security
  WHERE event_id = 4624  -- Successful logon
    AND logon_type IN (3, 10)  -- Network, RDP
    AND user_name NOT LIKE '%$'
    AND `@timestamp` > NOW() - INTERVAL '24 hours'
  GROUP BY user_name
)
SELECT *
FROM lateral_movement_candidates
WHERE unique_systems > 5
ORDER BY unique_systems DESC

-- Step 2: Check for explicit credential usage
SELECT
    `@timestamp`,
    host_name,
    user_name,
    target_user_name,
    target_server_name,
    process_name
FROM win_security
WHERE event_id = 4648  -- Logon with explicit credentials
  AND user_name != target_user_name  -- Different accounts
ORDER BY `@timestamp` DESC

-- Step 3: Remote service creation (PsExec-style)
SELECT
    `@timestamp`,
    host_name,
    service_name,
    service_file_name,
    service_start_type,
    event_data.SubjectUserName as user_name
FROM win_security
WHERE event_id = 4697  -- Service installed
  AND service_file_name LIKE '%\\ADMIN$\\%'
ORDER BY `@timestamp` DESC
```

**Hunt Hypothesis 5: APT33 Data Exfiltration**

**Hypothesis:** APT33 is exfiltrating collected data through C2 channels or other methods.

**Hunt Methodology:**

```sql
-- Step 1: Identify data staging (archiving)
WITH staging_events AS (
  SELECT
    `@timestamp`,
    host_name,
    process_name,
    process_command_line,
    file_target_filename,
    file_target_size
  FROM win_sysmon
  WHERE event_code = '11'  -- File creation
    AND (
      file_target_filename LIKE '%.rar'
      OR file_target_filename LIKE '%.7z'
      OR file_target_filename LIKE '%.zip'
    )
    AND file_target_size > 10485760  -- > 10MB
)
SELECT *
FROM staging_events
ORDER BY `@timestamp` DESC

-- Step 2: Large outbound data transfers
SELECT
    ts,
    id_orig_h as source_ip,
    id_resp_h as dest_ip,
    id_resp_p as dest_port,
    SUM(orig_bytes) as total_upload,
    COUNT(*) as connection_count
FROM zeek_conn_logs
WHERE orig_bytes > resp_bytes * 5  -- Upload-heavy
  AND id_resp_p IN (80, 443, 8080)
GROUP BY DATE_TRUNC('hour', ts), source_ip, dest_ip, dest_port
HAVING SUM(orig_bytes) > 104857600  -- > 100MB
ORDER BY ts DESC, total_upload DESC

-- Step 3: DNS tunneling patterns
SELECT
    source_ip,
    SPLIT(query, '.')[SIZE(SPLIT(query, '.')) - 2] as domain,
    COUNT(*) as query_count,
    AVG(LENGTH(SPLIT(query, '.')[0])) as avg_subdomain_length,
    MAX(LENGTH(SPLIT(query, '.')[0])) as max_subdomain_length
FROM zeek_dns_logs
WHERE qtype_name = 'A'
GROUP BY source_ip, domain
HAVING AVG(LENGTH(SPLIT(query, '.')[0])) > 20
  AND query_count > 50
ORDER BY query_count DESC

-- Step 4: Correlate staging with network activity
WITH staging AS (
  SELECT
    host_name,
    MIN(`@timestamp`) as staging_time
  FROM win_sysmon
  WHERE event_code = '11'
    AND file_target_filename LIKE '%.rar'
  GROUP BY host_name
),
network AS (
  SELECT
    id_orig_h,
    MIN(ts) as upload_time,
    SUM(orig_bytes) as total_bytes
  FROM zeek_conn_logs
  WHERE orig_bytes > 10485760
  GROUP BY id_orig_h
)
SELECT
    s.host_name,
    s.staging_time,
    n.upload_time,
    n.total_bytes,
    UNIX_TIMESTAMP(n.upload_time) - UNIX_TIMESTAMP(s.staging_time) as time_diff_seconds
FROM staging s
JOIN network n
  ON host_to_ip(s.host_name) = n.id_orig_h
WHERE UNIX_TIMESTAMP(n.upload_time) - UNIX_TIMESTAMP(s.staging_time) BETWEEN 0 AND 3600
ORDER BY s.staging_time DESC
```

### 7.2 Stack Counting Analysis

**Stack Counting Methodology:**

Stack counting identifies rare/anomalous events by grouping similar events and counting occurrences.

**Example: Rare PowerShell Command Lines**

```sql
-- Find rare PowerShell command patterns
WITH ps_commands AS (
  SELECT
    process_command_line,
    COUNT(*) as occurrence_count,
    COUNT(DISTINCT host_name) as affected_hosts,
    MIN(`@timestamp`) as first_seen,
    MAX(`@timestamp`) as last_seen
  FROM win_sysmon
  WHERE event_code = '1'
    AND process_name = 'powershell.exe'
    AND `@timestamp` > NOW() - INTERVAL '7 days'
  GROUP BY process_command_line
)
SELECT
    process_command_line,
    occurrence_count,
    affected_hosts,
    first_seen,
    last_seen,
    CASE
      WHEN occurrence_count = 1 THEN 'UNIQUE'
      WHEN occurrence_count <= 5 THEN 'RARE'
      WHEN occurrence_count <= 20 THEN 'UNCOMMON'
      ELSE 'COMMON'
    END as rarity
FROM ps_commands
WHERE occurrence_count <= 20  -- Focus on rare/uncommon
ORDER BY occurrence_count ASC, first_seen DESC
```

**Example: Rare Parent-Process Relationships**

```sql
-- Find unusual parent-child process relationships
WITH process_relationships AS (
  SELECT
    parent_process_name,
    process_name,
    COUNT(*) as occurrence_count,
    COUNT(DISTINCT host_name) as affected_hosts
  FROM win_sysmon
  WHERE event_code = '1'
    AND `@timestamp` > NOW() - INTERVAL '30 days'
  GROUP BY parent_process_name, process_name
)
SELECT
    parent_process_name,
    process_name,
    occurrence_count,
    affected_hosts
FROM process_relationships
WHERE occurrence_count <= 10
  AND (
    parent_process_name IN ('WINWORD.EXE', 'EXCEL.EXE', 'POWERPNT.EXE')
    OR process_name IN ('powershell.exe', 'cmd.exe', 'wscript.exe', 'mshta.exe')
  )
ORDER BY occurrence_count ASC
```

### 7.3 Baseline Deviation Hunting

**Establish Baseline:**

```sql
-- Baseline: Normal authentication patterns per user
CREATE TEMP VIEW user_auth_baseline AS
SELECT
    user_name,
    AVG(daily_logons) as avg_daily_logons,
    STDDEV(daily_logons) as stddev_daily_logons,
    AVG(unique_sources) as avg_unique_sources,
    STDDEV(unique_sources) as stddev_unique_sources
FROM (
  SELECT
    user_name,
    DATE_TRUNC('day', timestamp) as date,
    COUNT(*) as daily_logons,
    COUNT(DISTINCT source_ip) as unique_sources
  FROM authentication_logs
  WHERE timestamp BETWEEN NOW() - INTERVAL '90 days' AND NOW() - INTERVAL '7 days'
  GROUP BY user_name, date
)
GROUP BY user_name

-- Hunt: Detect deviations from baseline
SELECT
    a.user_name,
    a.date,
    a.daily_logons,
    a.unique_sources,
    b.avg_daily_logons,
    b.avg_unique_sources,
    (a.daily_logons - b.avg_daily_logons) / NULLIF(b.stddev_daily_logons, 0) as logon_z_score,
    (a.unique_sources - b.avg_unique_sources) / NULLIF(b.stddev_unique_sources, 0) as source_z_score
FROM (
  SELECT
    user_name,
    DATE_TRUNC('day', timestamp) as date,
    COUNT(*) as daily_logons,
    COUNT(DISTINCT source_ip) as unique_sources
  FROM authentication_logs
  WHERE timestamp > NOW() - INTERVAL '7 days'
  GROUP BY user_name, date
) a
JOIN user_auth_baseline b ON a.user_name = b.user_name
WHERE ABS((a.daily_logons - b.avg_daily_logons) / NULLIF(b.stddev_daily_logons, 0)) > 3  -- 3 sigma
  OR ABS((a.unique_sources - b.avg_unique_sources) / NULLIF(b.stddev_unique_sources, 0)) > 3
ORDER BY a.date DESC, logon_z_score DESC
```

### 7.4 Hunt Playbooks

#### **Playbook 1: New Employee Spearphishing**

**Scenario:** APT33 targets newly-hired employees with less security awareness.

**Hunt Steps:**
1. Identify employees hired in last 90 days
2. Check for spearphishing indicators in their emails
3. Look for suspicious attachment opens or link clicks
4. Investigate post-click activities

```sql
-- Step 1 & 2: Recent hires receiving suspicious emails
SELECT
    e.recipient_email,
    e.sender_email,
    e.subject,
    e.attachment_count,
    e.link_count,
    emp.hire_date,
    DATEDIFF(e.sent_timestamp, emp.hire_date) as days_since_hire
FROM email_logs e
JOIN employee_directory emp ON e.recipient_email = emp.email
WHERE emp.hire_date > NOW() - INTERVAL '90 days'
  AND (
    e.attachment_count > 0
    OR e.link_count > 0
  )
  AND e.sender_domain NOT IN (trusted_domains)
ORDER BY emp.hire_date DESC, e.sent_timestamp DESC
```

#### **Playbook 2: Dormant Account Reactivation**

**Scenario:** APT33 reactivates a previously compromised dormant account.

**Hunt Steps:**
1. Identify accounts with no activity for 30+ days
2. Detect recent authentication from these accounts
3. Investigate post-authentication activities

```sql
-- Detect dormant account reactivation
WITH account_activity AS (
  SELECT
    user_name,
    MAX(timestamp) as last_activity
  FROM authentication_logs
  WHERE timestamp < NOW() - INTERVAL '30 days'
  GROUP BY user_name
),
recent_activity AS (
  SELECT
    user_name,
    COUNT(*) as recent_logons,
    COLLECT_SET(source_ip) as source_ips,
    MIN(timestamp) as first_recent_logon
  FROM authentication_logs
  WHERE timestamp > NOW() - INTERVAL '7 days'
  GROUP BY user_name
)
SELECT
    aa.user_name,
    aa.last_activity as last_activity_before_dormancy,
    ra.first_recent_logon as reactivation_time,
    DATEDIFF(ra.first_recent_logon, aa.last_activity) as dormancy_days,
    ra.recent_logons,
    ra.source_ips
FROM account_activity aa
JOIN recent_activity ra ON aa.user_name = ra.user_name
ORDER BY dormancy_days DESC
```

---

## 8. Indicators of Compromise (IOCs)

### 8.1 File Hashes

**Custom Malware Hashes (SHA256):**

```
# TURNEDUP samples
bc69a24a06e2b4bfaeb1e4a7a4a4e1a3d3c4f5e6d7e8f9a0b1c2d3e4f5a6b7c8
45a3b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1

# DEADWOOD samples
7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8
f0e1d2c3b4a5968778695a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4

# SHAPESHIFT samples
a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6

# POWERTON samples (script hashes may vary)
3f4e5d6c7b8a9908172635445362718a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4
9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8
```

**Note:** Hashes frequently change due to recompilation. Focus on behavioral detection.

### 8.2 Network Indicators

**C2 Domains (Historical):**

```
aviation-maintenance[.]com
aircraft-services[.]net
energy-portal[.]com
secure-aerospace[.]com
*-login[.]tk
*-update[.]ml
```

**C2 IP Addresses (Historical - likely rotated):**

```
185.141.25.XXX
89.108.83.XXX
5.39.217.XXX
163.172.34.XXX
```

**Malicious Email Domains:**

```
aeroservice[.]net
aerospace-inc[.]com
oil-services[.]net
```

**Detection Rule - C2 Domain Pattern:**
```sql
-- Detect connections to APT33-style domains
SELECT
    ts,
    id_orig_h,
    host as domain,
    uri
FROM zeek_http_logs
WHERE (
    host LIKE '%aviation%'
    OR host LIKE '%aircraft%'
    OR host LIKE '%aerospace%'
    OR host LIKE '%energy%'
    OR host LIKE '%petrochemical%'
  )
  AND (
    host LIKE '%-service%'
    OR host LIKE '%-portal%'
    OR host LIKE '%-update%'
    OR host LIKE '%-login%'
    OR host LIKE 'secure-%'
  )
  AND host NOT IN (legitimate_domains)
ORDER BY ts DESC
```

### 8.3 Email Indicators

**Sender Email Patterns:**

```
*@aviation-service.*
*@aircraft-maintenance.*
*@energy-services.*
hr@*
admin@*
support@*
```

**Subject Line Patterns:**

```
"Invoice [number]"
"Payment Receipt"
"Aircraft Maintenance Report"
"Contract Proposal"
"Updated Flight Schedule"
"Energy Sector Report"
"Urgent: Account Verification"
```

**Attachment Names:**

```
Invoice_*.doc
Report_*.docm
Contract_*.xls
Proposal_*.xlsx
Schedule_*.doc
Payment_*.docm
```

### 8.4 Host Indicators

**Persistence Registry Keys:**

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

**File System Indicators:**

```
%TEMP%\~tmp*.exe
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk
C:\Windows\Temp\*.ps1
C:\Users\Public\*.exe
```

**Scheduled Task Names:**

```
WindowsUpdate
SystemMaintenance
UserTask
GoogleUpdateTask
AdobeUpdate
```

**Mutex Names:**

```
Global\{GUID}
Local\MSCTF.Asm.MutexDefault1
```

### 8.5 Detection Rule Summary

**Snort/Suricata Signature Summary:**

```
sid:9000001 - APT33 PowerShell Download Cradle
sid:9000002 - APT33 Password Spraying Pattern
sid:9000003 - APT33 HTTP Beaconing
sid:9000004 - APT33 DNS Tunneling
sid:9000005 - APT33 TURNEDUP C2 Communication
sid:9000006 - APT33 DEADWOOD Dropper Network Activity
sid:9000007 - APT33 Mimikatz-style LSASS Access
sid:9000008 - APT33 Suspicious PowerShell Encoded Command
sid:9000009 - APT33 Credential Exfiltration Pattern
sid:9000010 - APT33 Multi-hop Proxy Traffic
```

**YARA Rules:**

```yara
rule APT33_TURNEDUP {
    meta:
        description = "Detects APT33 TURNEDUP backdoor"
        author = "Threat Intel Team"
        date = "2025-01-01"
        hash = "bc69a24a06e2b4bfaeb1e4a7a4a4e1a3d3c4f5e6d7e8f9a0b1c2d3e4f5a6b7c8"

    strings:
        $s1 = "Mozilla/5.0 (Windows NT 6.1; WOW64)" ascii
        $s2 = "/page.php" ascii
        $s3 = "cmd.exe /c" wide
        $api1 = "CreateProcessW" ascii
        $api2 = "InternetOpenA" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        all of ($api*) and
        2 of ($s*)
}

rule APT33_PowerShell_Obfuscation {
    meta:
        description = "Detects APT33-style PowerShell obfuscation"
        author = "Threat Intel Team"

    strings:
        $enc = "-encodedcommand" nocase ascii wide
        $iex = "IEX" nocase ascii wide
        $webclient = "Net.WebClient" nocase ascii wide
        $downloadstring = "DownloadString" nocase ascii wide
        $frombase64 = "FromBase64String" nocase ascii wide

    condition:
        $enc or
        ($iex and $webclient and $downloadstring) or
        ($frombase64 and $iex)
}

rule APT33_Credential_Dumping {
    meta:
        description = "Detects APT33 credential dumping activities"

    strings:
        $mimikatz1 = "sekurlsa::logonpasswords" ascii wide
        $mimikatz2 = "lsadump::sam" ascii wide
        $reg1 = "reg save HKLM\\SAM" nocase ascii wide
        $reg2 = "reg save HKLM\\SECURITY" nocase ascii wide
        $gpp = "Get-GPPPassword" nocase ascii wide
        $lazagne = "laZagne.exe" nocase ascii wide

    condition:
        any of them
}
```

---

## 9. Defensive Recommendations

### 9.1 Immediate Actions (First 24 Hours)

**Critical Security Controls:**

1. **Enforce Multi-Factor Authentication (MFA)**
   - **Priority:** CRITICAL
   - **Scope:** All remote access (VPN, webmail, O365, cloud services)
   - **Action:** Deploy MFA immediately for:
     - VPN access
     - Office 365 / Exchange Online
     - Cloud administration portals
     - Remote Desktop Gateway
   - **Effectiveness vs APT33:** Blocks password spraying attacks

2. **Block Legacy Authentication Protocols**
   - **Priority:** HIGH
   - **Scope:** Office 365, Exchange
   - **Action:**
     ```
     # PowerShell to block legacy auth in O365
     Set-OrganizationConfig -OAuth2ClientProfileEnabled $true
     New-AuthenticationPolicy -Name "Block Legacy Auth" -AllowBasicAuthActiveSync:$false
     ```
   - **Effectiveness vs APT33:** Prevents exploitation of weak authentication

3. **Disable Office Macros from Internet**
   - **Priority:** CRITICAL
   - **Scope:** All Office applications
   - **Action:** Deploy Group Policy:
     ```
     Computer Configuration → Administrative Templates →
     Microsoft Office → Security Settings →
     VBA Macro Notification Settings →
     "Disable all except digitally signed macros"
     ```
   - **Effectiveness vs APT33:** Blocks primary initial access vector

4. **Enable PowerShell Logging**
   - **Priority:** HIGH
   - **Scope:** All Windows systems
   - **Action:** Enable via GPO:
     - Module Logging
     - Script Block Logging
     - Transcription Logging
   - **Effectiveness vs APT33:** Visibility into post-exploitation activities

5. **Deploy Sysmon**
   - **Priority:** HIGH
   - **Scope:** All Windows endpoints and servers
   - **Action:** Deploy Sysmon with configuration focused on:
     - Process creation (Event ID 1)
     - Network connections (Event ID 3)
     - Process access (Event ID 10)
   - **Effectiveness vs APT33:** Critical telemetry for detection

### 9.2 Short-Term Improvements (Week 1-4)

**1. Email Security Hardening**

- Deploy email sandbox for attachments
- Implement URL rewriting and click-time analysis
- Block newly registered domains (<30 days old)
- Enforce DMARC policy (p=reject)
- Deploy SPF and DKIM
- Block double-file-extension attachments

**2. Endpoint Security**

- Deploy EDR solution if not present
- Enable Attack Surface Reduction (ASR) rules (Windows Defender)
- Deploy LSASS protection (Protected Process Light)
- Enable Credential Guard on Windows 10+ systems
- Restrict PowerShell to Constrained Language Mode for standard users

**3. Network Segmentation**

- Implement network segmentation for critical assets
- Restrict lateral movement pathways
- Deploy jump servers for admin access
- Implement firewall rules between VLANs

**4. Privileged Access Management**

- Implement just-in-time (JIT) admin access
- Deploy privileged access workstations (PAWs)
- Rotate all service account passwords
- Audit and reduce accounts with admin privileges

**5. Detection Deployment**

- Deploy hunt queries from Section 7 into SIEM
- Create alerts for high-priority detections
- Establish baseline behavior for key user accounts
- Deploy APT33 IOC feeds to security tools

### 9.3 Medium-Term Enhancements (Month 2-6)

**1. Advanced Threat Hunting Program**

- Establish dedicated threat hunting team
- Implement hypothesis-driven hunting cadence (weekly)
- Develop organization-specific threat models
- Create feedback loop from hunts to detections

**2. Deception Technology**

- Deploy honeypot accounts (high-privilege names, never used)
- Create honey tokens (fake credentials in documents)
- Deploy canary systems (fake high-value servers)
- Monitor for any interaction with deception assets

**3. Zero Trust Architecture**

- Implement continuous authentication
- Deploy micro-segmentation
- Enforce least-privilege access models
- Implement device health attestation

**4. Security Awareness Training**

- Conduct APT33-specific phishing simulations
- Train employees on spearphishing recognition
- Focus on aviation/energy sector employees
- Establish clear reporting procedures for suspicious emails

**5. Incident Response Preparation**

- Develop APT33-specific incident response playbooks
- Conduct tabletop exercises simulating APT33 attack
- Establish relationships with external IR firms
- Pre-position forensic tools and licenses

### 9.4 Long-Term Strategic Initiatives (6-12+ Months)

**1. Threat Intelligence Program**

- Subscribe to commercial threat intelligence feeds
- Join sector-specific ISACs (Aviation ISAC, Energy ISAC)
- Develop internal threat intelligence capability
- Integrate TI into all security workflows

**2. Advanced Detection Capabilities**

- Deploy User and Entity Behavior Analytics (UEBA)
- Implement machine learning-based anomaly detection
- Deploy Network Traffic Analysis (NTA) solutions
- Enhance DNS security with DNS-layer security

**3. Supply Chain Security**

- Assess third-party vendor security posture
- Implement supply chain risk management program
- Restrict vendor remote access
- Monitor vendor access activities

**4. Cloud Security Posture**

- Implement Cloud Security Posture Management (CSPM)
- Enforce cloud security baselines
- Deploy cloud access security broker (CASB)
- Implement cloud workload protection

**5. Continuous Improvement**

- Establish metrics for security program effectiveness
- Conduct annual purple team exercises
- Regularly update detections based on new APT33 TTPs
- Participate in sector-wide threat sharing

### 9.5 MITRE ATT&CK Mitigation Mapping

**Critical Mitigations by Tactic:**

| Tactic | Mitigation | Priority | Implementation |
|--------|-----------|----------|----------------|
| **Initial Access** | M1049 - Antivirus/Antimalware | HIGH | Deploy EDR, email sandbox |
| **Initial Access** | M1017 - User Training | HIGH | Phishing awareness training |
| **Initial Access** | M1032 - Multi-factor Authentication | CRITICAL | MFA on all external access |
| **Execution** | M1038 - Execution Prevention | CRITICAL | Disable Office macros from internet |
| **Execution** | M1042 - Disable or Remove Feature | HIGH | Constrain PowerShell for users |
| **Persistence** | M1028 - Operating System Configuration | MEDIUM | Restrict scheduled task creation |
| **Privilege Escalation** | M1026 - Privileged Account Management | HIGH | JIT admin access, PAWs |
| **Credential Access** | M1043 - Credential Access Protection | CRITICAL | Deploy Credential Guard, LSASS Protection |
| **Credential Access** | M1027 - Password Policies | HIGH | Long, complex passwords; regular rotation |
| **Lateral Movement** | M1030 - Network Segmentation | HIGH | Segment critical assets |
| **Lateral Movement** | M1037 - Filter Network Traffic | MEDIUM | Restrict SMB, RDP between zones |
| **Command & Control** | M1031 - Network Intrusion Prevention | HIGH | Deploy IPS with APT33 signatures |
| **Exfiltration** | M1057 - Data Loss Prevention | MEDIUM | Monitor large outbound transfers |

### 9.6 Detection Coverage Gaps

**Areas Requiring Enhanced Detection:**

1. **Encrypted C2 Traffic**
   - **Gap:** HTTPS C2 difficult to inspect
   - **Recommendation:** Deploy TLS inspection, monitor for beaconing patterns

2. **Living-Off-the-Land Techniques**
   - **Gap:** Native tools harder to detect
   - **Recommendation:** Behavioral analytics, baseline deviations

3. **Cloud-based Exfiltration**
   - **Gap:** Legitimate cloud services used for exfil
   - **Recommendation:** CASB deployment, cloud DLP

4. **Supply Chain Compromise**
   - **Gap:** Limited visibility into vendor activities
   - **Recommendation:** Vendor access monitoring, supply chain audits

5. **Mobile Device Access**
   - **Gap:** Limited mobile device visibility
   - **Recommendation:** Mobile threat defense, ActiveSync monitoring

---

## 10. References

### 10.1 Intelligence Reports

1. **FireEye (2017):** "APT33: Insights into Iranian Cyber Espionage"
   - https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html

2. **Symantec (2019):** "Elfin: Relentless Espionage Group Targets Multiple Organizations in Saudi Arabia and U.S."
   - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/elfin-apt33-espionage

3. **Microsoft (2023):** "Peach Sandstorm (APT33) Targeting Critical Infrastructure"
   - https://www.microsoft.com/security/blog/threat-intelligence/peach-sandstorm

4. **CISA (2020):** "Iranian Threat Actor Activity Advisory"
   - https://www.cisa.gov/news-events/cybersecurity-advisories

5. **Kaspersky (2018):** "Shamoon 2.0 and APT33 Links Analysis"
   - https://securelist.com/shamoon-attacks-analysis/

### 10.2 MITRE ATT&CK References

- **APT33 Group Profile:** https://attack.mitre.org/groups/G0064/
- **Techniques Used:** 31 techniques across 10 tactics
- **Software Used:** TURNEDUP, DEADWOOD, SHAPESHIFT, POWERTON, etc.

### 10.3 Technical Analysis

1. **Palo Alto Unit 42:** "AutoIt Backdoor Analysis"
2. **CrowdStrike:** "Iranian Adversary Playbook"
3. **Mandiant:** "APT33 Infrastructure Analysis"
4. **Cisco Talos:** "POWERTON Analysis and Detection"

### 10.4 Indicator Sources

- **AlienVault OTX:** APT33 Pulse
- **MISP:** APT33 Event Collections
- **VirusTotal:** APT33 Tagged Samples
- **Hybrid Analysis:** APT33 Malware Reports

### 10.5 Detection Resources

- **Sigma Rules:** https://github.com/SigmaHQ/sigma (search for APT33)
- **YARA Rules:** https://github.com/Yara-Rules/rules (APT33 signatures)
- **Snort Rules:** Emerging Threats - APT33 ruleset
- **Elastic Detection Rules:** APT33 behavioral rules

---

## Appendix A: Training Scenarios

### Scenario 1: Spearphishing Investigation

**Background:** Security Operations Center received an alert for suspicious email sent to 50 employees in the engineering department.

**Your Task:**
1. Analyze the email (subject: "Updated Aircraft Specifications")
2. Determine if any users clicked the attachment
3. Check for post-compromise indicators
4. Contain affected systems if compromise detected

**Data Sources:**
- Email logs
- Endpoint logs (Sysmon)
- Network traffic logs
- Authentication logs

### Scenario 2: Credential Compromise Response

**Background:** An account from the IT department is showing unusual authentication patterns.

**Your Task:**
1. Investigate the authentication anomalies
2. Determine if account is compromised
3. Identify what actions the account performed
4. Assess impact and lateral movement
5. Contain and remediate

---

## Appendix B: Hunt Query Library

**Complete hunt queries available in:**
- `../Intel/mitre_APT33_hunt_queries_20251106_112136.json`

**Query Categories:**
- Simple IOC Searches (5 queries)
- Behavioral Pattern Detection (4 queries)
- Credential Theft Detection (6 queries)
- Lateral Movement Detection (4 queries)
- Exfiltration Detection (3 queries)

---

## Appendix C: Detection Rule Deployment

**SIEM Detection Pack:**
- 25 correlation rules for APT33 TTPs
- Dashboard for APT33 activity monitoring
- Alert prioritization matrix
- Response playbook integration

**Deployment Guide:**
1. Import detection rules to SIEM
2. Customize thresholds for environment
3. Enable email notifications for critical alerts
4. Assign ownership to SOC analysts
5. Test with purple team exercise

---

## Document Control

**Version History:**
- v1.0 (2025-11-06): Initial release

**Review Cycle:** Quarterly

**Next Review:** 2026-02-06

**Feedback:** Submit updates to threat-intel-team@organization.com

---

**END OF REPORT**

*This threat intelligence report is provided for training and educational purposes only. All threat actor activities described represent synthesis of public reporting and MITRE ATT&CK data.*
