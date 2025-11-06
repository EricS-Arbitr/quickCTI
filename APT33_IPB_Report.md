# APT33 Intelligence Preparation of the Battlefield (IPB)

**Classification:** UNCLASSIFIED // FOR TRAINING USE ONLY
**Report Type:** Intelligence Preparation of the Battlefield (IPB)
**Subject:** APT33 (HOLMIUM / Elfin / Peach Sandstorm)
**Date:** November 6, 2025
**Prepared By:** Cyber Intelligence Preparation Team
**Distribution:** Training Exercise Use Only

---

## Executive Summary

This Intelligence Preparation of the Battlefield (IPB) provides a systematic analysis of APT33, an Iranian state-sponsored cyber threat actor, within the context of critical infrastructure defense operations. This analysis follows the four-step IPB methodology to enable defenders to anticipate adversary actions and prepare effective defensive measures.

**Key Intelligence Judgments:**

- **HIGH CONFIDENCE:** APT33 will continue targeting U.S. and Saudi Arabian aviation and energy sectors
- **MODERATE CONFIDENCE:** APT33 possesses destructive cyber capabilities and may deploy them if regional tensions escalate
- **MODERATE CONFIDENCE:** APT33 coordinates with other Iranian APT groups for access sharing and operational deconfliction
- **LOW CONFIDENCE:** APT33 has limited capability against highly segmented OT/ICS environments

**Threat Level:** HIGH for aviation and energy sectors
**Operational Tempo:** Sustained (continuous operations since 2013)
**Recommended Defensive Posture:** INFOCON 3 → INFOCON 2 for high-value targets

---

## Table of Contents

1. [IPB Step 1: Define the Operational Environment](#step-1-define-the-operational-environment)
2. [IPB Step 2: Describe Environmental Effects](#step-2-describe-environmental-effects)
3. [IPB Step 3: Evaluate the Adversary](#step-3-evaluate-the-adversary)
4. [IPB Step 4: Determine Adversary Courses of Action](#step-4-determine-adversary-courses-of-action)
5. [Intelligence Gaps and Collection Requirements](#intelligence-gaps-and-collection-requirements)
6. [Recommended Actions](#recommended-actions)
7. [Appendices](#appendices)

---

## Step 1: Define the Operational Environment

### 1.1 Area of Interest (AOI)

**Geographic Scope:**
- **Primary:** United States, Saudi Arabia, South Korea
- **Secondary:** United Arab Emirates, Kuwait, Qatar
- **Tertiary:** European aviation/energy infrastructure

**Cyber Terrain:**
- Public-facing web applications (VPN, webmail, cloud services)
- Enterprise IT networks (Windows Active Directory environments)
- Email infrastructure (Exchange, Office 365)
- Industrial control systems (limited but increasing interest)
- Cloud infrastructure (AWS, Azure, Office 365)

**Sector Focus:**
```
HIGH PRIORITY (60-70% of operations)
├── Commercial Aviation
│   ├── Airlines
│   ├── Aerospace manufacturers
│   ├── Airport authorities
│   └── MRO (Maintenance, Repair, Overhaul) facilities
│
└── Energy & Petrochemical
    ├── Oil & gas extraction
    ├── Refineries
    ├── Petrochemical plants
    └── Pipeline operators

MEDIUM PRIORITY (20-30%)
├── Defense Industrial Base
│   ├── Military aviation contractors
│   ├── Defense R&D facilities
│   └── Aerospace component manufacturers
│
└── Government
    ├── Department of Energy
    ├── Transportation Security Administration
    └── Defense agencies

LOW PRIORITY (5-10%)
├── Financial services
├── Telecommunications
└── Higher education (research institutions)
```

### 1.2 Area of Operations (AO)

**Named Areas of Interest (NAI):**

| NAI | Description | Geographic Location | Priority |
|-----|-------------|-------------------|----------|
| NAI-1 | U.S. Commercial Aviation | United States | CRITICAL |
| NAI-2 | Saudi Energy Sector | Saudi Arabia | CRITICAL |
| NAI-3 | U.S. Energy Infrastructure | United States | HIGH |
| NAI-4 | South Korean Aviation/Defense | South Korea | HIGH |
| NAI-5 | Gulf Cooperation Council (GCC) Energy | UAE, Kuwait, Qatar | MEDIUM |
| NAI-6 | European Aerospace | UK, France, Germany | MEDIUM |

**Targeted Asset Evaluation Criteria (TAEC):**

APT33 prioritizes targets based on:
1. **Strategic Intelligence Value** (30%)
   - Access to proprietary aerospace technology
   - Energy sector strategic plans
   - Defense contract information

2. **Iranian Foreign Policy Alignment** (25%)
   - Saudi Arabian entities (adversary)
   - U.S. entities involved in sanctions enforcement
   - Regional competitors

3. **Accessibility** (25%)
   - Internet-facing authentication portals
   - Third-party vendor access
   - Cloud service adoption

4. **Collection Requirements** (20%)
   - Specific intelligence gaps identified by Iranian leadership
   - Technology transfer opportunities
   - Competitive intelligence

### 1.3 Battlespace Geometry

**Cyber Terrain Analysis:**

```
LAYER 1: PERIMETER (Initial Access Zone)
├── External Attack Surface
│   ├── VPN gateways (Cisco AnyConnect, Pulse Secure, Palo Alto GlobalProtect)
│   ├── Webmail portals (Outlook Web Access, Office 365)
│   ├── Public websites (WordPress, custom applications)
│   ├── Cloud services (AWS, Azure, Office 365)
│   └── Remote access solutions (Citrix, VMware Horizon)
│
└── Human Attack Surface
    ├── Email users (spearphishing targets)
    ├── LinkedIn-visible employees
    └── Contractors with remote access

LAYER 2: ENTERPRISE IT (Expansion Zone)
├── Windows Active Directory Domain
├── File servers and collaboration platforms
├── Email infrastructure (Exchange, O365)
├── Workstations and laptops
└── Administrator accounts and privileged access

LAYER 3: SENSITIVE DATA (Objective Zone)
├── Engineering design repositories
├── Executive email archives
├── Strategic planning documents
├── Intellectual property databases
└── Financial/contract information

LAYER 4: OPERATIONAL TECHNOLOGY (Potential Future Target)
├── SCADA systems
├── Industrial control systems
├── Safety instrumented systems
└── Building management systems
```

**Key Terrain Features:**

1. **Active Directory Domain Controllers**
   - Critical for lateral movement
   - Primary target for credential harvesting
   - Control point for domain-wide access

2. **Email Infrastructure**
   - Initial access vector (spearphishing)
   - Intelligence collection target
   - Potential for further phishing from compromised accounts

3. **VPN/Remote Access Gateways**
   - Entry point for password spraying
   - Persistent access mechanism
   - Difficult to monitor/detect external authentication

4. **Cloud Identity Providers**
   - Office 365/Azure AD
   - Single sign-on (SSO) platforms
   - High-value authentication targets

5. **Jump Servers / Privileged Access Workstations**
   - Choke points for administrative access
   - High-value targets for credential theft
   - Critical for OT network access

### 1.4 Timeline and Operational Tempo

**Historical Operations Cadence:**

```
PHASE 1: RECONNAISSANCE & INFRASTRUCTURE SETUP
Timeline: Weeks 1-4
Tempo: Low intensity, continuous
Activities: OSINT, infrastructure acquisition, phishing list development

PHASE 2: INITIAL ACCESS CAMPAIGNS
Timeline: Weeks 4-8
Tempo: Medium intensity, wave-based
Activities: Spearphishing campaigns, password spraying, exploitation

PHASE 3: POST-COMPROMISE OPERATIONS
Timeline: Weeks 8-20
Tempo: Low-medium intensity, persistent
Activities: Credential harvesting, lateral movement, reconnaissance

PHASE 4: MISSION COMPLETION
Timeline: Weeks 20-40+
Tempo: Variable
Activities: Data exfiltration, persistence establishment, [optional] destructive actions
```

**Operational Patterns:**

- **Campaign Duration:** 3-9 months average
- **Dwell Time:** 90-180 days before detection (historical average)
- **Operational Hours:** 0600-1800 UTC (Iranian business hours) - 70% of activity
- **Weekend Activity:** Reduced (Friday-Saturday - Iranian weekend)
- **Holiday Dormancy:** Significant reduction during Iranian holidays (Nowruz, Ramadan)

### 1.5 Weather and Environmental Factors (Cyber Context)

**Factors Affecting Operations:**

1. **Geopolitical Climate**
   - **Current State:** Elevated tensions (Iran nuclear program, regional conflicts)
   - **Effect:** Increases operational tempo and risk tolerance
   - **Forecast:** Sustained high threat level through 2025-2026

2. **International Sanctions**
   - **Effect:** Motivates espionage against energy sector
   - **Collection Priority:** Energy market intelligence, sanctions evasion methods
   - **Forecast:** Continued targeting as sanctions remain in place

3. **Regional Conflicts**
   - **Saudi-Iran Relations:** Adversarial
   - **Israel-Iran Relations:** Adversarial
   - **Effect:** Increases destructive capability deployment risk
   - **Forecast:** If military conflict escalates, expect destructive cyber operations

4. **Technology Adoption Trends**
   - **Cloud Migration:** Expanding attack surface for APT33
   - **Multi-Factor Authentication:** Reducing password spray success rate
   - **Zero Trust Architecture:** Forcing adversary TTP evolution
   - **Forecast:** APT33 will adapt to MFA with OTP phishing, token theft

5. **Threat Landscape Evolution**
   - **Defensive Improvements:** Organizations hardening against Iranian threats
   - **Law Enforcement Actions:** Occasional disruption of infrastructure
   - **Information Sharing:** Increased IOC dissemination
   - **Effect:** APT33 operational costs increasing, forcing efficiency improvements

---

## Step 2: Describe Environmental Effects

### 2.1 Terrain Analysis (Cyber)

#### 2.1.1 Observation and Fields of Fire (Visibility)

**Defender Observation Capabilities:**

| Asset/Terrain | Defender Visibility | APT33 Counters |
|--------------|---------------------|----------------|
| **External Perimeter** | HIGH - Firewall logs, IDS/IPS | Legitimate cloud services, compromised infrastructure |
| **Email Gateway** | HIGH - Email security solutions | Polymorphic attachments, credential harvesting links |
| **Endpoint (Workstations)** | MEDIUM - AV/EDR coverage gaps | Living-off-the-land, legitimate tools, fileless malware |
| **Network Traffic** | MEDIUM - Limited TLS inspection | Encrypted C2 (HTTPS), DNS tunneling |
| **Authentication** | MEDIUM - Log retention/analysis varies | Low-and-slow password spraying, compromised VPN |
| **Cloud Services** | LOW-MEDIUM - Limited visibility | Native cloud tools, OAuth token theft |
| **Privileged Access** | HIGH - PAM solutions (where deployed) | Credential dumping before PAM, Pass-the-Hash |
| **Lateral Movement** | LOW - Limited east-west visibility | SMB, RDP, WMI - appear legitimate |

**APT33 Counter-Observation Techniques:**

1. **Blending with Legitimate Traffic**
   - PowerShell execution via legitimate admin tools
   - C2 over HTTPS to compromised WordPress sites
   - DNS queries appearing as normal lookups

2. **Timing-Based Evasion**
   - Operations during business hours (appear as normal activity)
   - Low-and-slow password spraying (below threshold)
   - Delayed execution (wait 30+ days before suspicious activity)

3. **Encrypted Communications**
   - TLS-encrypted C2 channels
   - Base64/XOR obfuscation of payloads
   - Encrypted archives for exfiltration

#### 2.1.2 Avenues of Approach

**Primary Avenues:**

```
AVENUE 1: SPEARPHISHING → MACRO EXECUTION → POWERSHELL → C2
├── Entry: Email gateway
├── Execution: User workstation
├── Expansion: Credential dumping → Lateral movement
├── Objective: Domain admin access → Data exfiltration
├── Success Rate: Medium (10-30% click rate, 1-5% execution)
├── Detection Risk: Medium (email filtering, EDR)
└── Defender Counter: Email security, macro blocking, PowerShell logging

AVENUE 2: PASSWORD SPRAYING → VPN ACCESS → INTERNAL NETWORK
├── Entry: VPN gateway
├── Execution: Internal network access with valid credentials
├── Expansion: Immediate lateral movement capability
├── Objective: Persistence, data access
├── Success Rate: Low-Medium (1-5% of accounts typically compromise)
├── Detection Risk: Low (appears as failed logins, often not alerted)
└── Defender Counter: MFA, account lockout policies, anomaly detection

AVENUE 3: EXPLOIT PUBLIC APPLICATION → WEB SHELL → PIVOT
├── Entry: Public-facing web application
├── Execution: Web server
├── Expansion: Pivot to internal network
├── Objective: Network access, credential harvesting
├── Success Rate: Low (requires vulnerability, mature defender patching)
├── Detection Risk: Medium (WAF, file integrity monitoring)
└── Defender Counter: Patch management, WAF, application security testing

AVENUE 4: SUPPLY CHAIN → TRUSTED THIRD PARTY → CUSTOMER ACCESS
├── Entry: IT service provider, contractor portal
├── Execution: Third-party network → customer network
├── Expansion: Leverage trust relationship
├── Objective: Multiple customer access
├── Success Rate: Low (requires supply chain compromise)
├── Detection Risk: Very Low (trusted source)
└── Defender Counter: Third-party risk management, vendor monitoring
```

**Terrain Trafficability Assessment:**

| Avenue | Speed | Capacity | Vulnerability | Overall Rating |
|--------|-------|----------|---------------|----------------|
| Spearphishing | Fast (hours-days) | High (many users) | Medium-High | PRIMARY |
| Password Spraying | Medium (days-weeks) | Medium (susceptible accounts) | Low-Medium | PRIMARY |
| Public Exploit | Fast (hours) | Low (limited apps) | Medium | SECONDARY |
| Supply Chain | Slow (months) | High (multiple orgs) | Very Low | OPPORTUNISTIC |

#### 2.1.3 Key Terrain

**Most Critical Assets for Control:**

1. **DOMAIN CONTROLLERS (CRITICAL)**
   - **Value:** Complete domain control, all credentials, Group Policy
   - **APT33 Objective:** Credential dumping, lateral movement, persistence
   - **Defender Priority:** Maximum protection, monitoring, segmentation

2. **EMAIL INFRASTRUCTURE (CRITICAL)**
   - **Value:** Communication access, further phishing, intelligence collection
   - **APT33 Objective:** Email archives, contact lists, internal communications
   - **Defender Priority:** Logging, backup, access control

3. **PRIVILEGED ACCESS MANAGEMENT (PAM) SYSTEMS (HIGH)**
   - **Value:** Administrative credential storage and access
   - **APT33 Objective:** Credentials for critical systems
   - **Defender Priority:** Hardening, monitoring, MFA enforcement

4. **FILE SERVERS / DOCUMENT REPOSITORIES (HIGH)**
   - **Value:** Intellectual property, strategic documents
   - **APT33 Objective:** Data exfiltration
   - **Defender Priority:** Access control, DLP, monitoring

5. **VPN / REMOTE ACCESS GATEWAYS (HIGH)**
   - **Value:** External network access, remote workforce entry point
   - **APT33 Objective:** Initial access, persistent access
   - **Defender Priority:** MFA, logging, anomaly detection

6. **CLOUD IDENTITY PROVIDERS (HIGH)**
   - **Value:** SSO access to multiple applications
   - **APT33 Objective:** Lateral movement to cloud services
   - **Defender Priority:** Conditional access, MFA, monitoring

7. **JUMP SERVERS (MEDIUM-HIGH)**
   - **Value:** Administrative access to OT, servers
   - **APT33 Objective:** Privileged access, OT network entry
   - **Defender Priority:** Hardening, monitoring, session recording

#### 2.1.4 Obstacles

**Defender Obstacles to APT33:**

```
STRONG OBSTACLES (High Effectiveness)
├── Multi-Factor Authentication (MFA)
│   └── Effect: Defeats password spraying, reduces phish success
├── Application Whitelisting
│   └── Effect: Prevents malware execution, limits tools
├── Network Segmentation
│   └── Effect: Limits lateral movement, contains compromise
├── Privileged Access Management (PAM)
│   └── Effect: Reduces credential exposure, logs admin activity
└── Email Security (Sandbox, Link Protection)
    └── Effect: Blocks malicious attachments/links

MODERATE OBSTACLES (Medium Effectiveness)
├── Endpoint Detection and Response (EDR)
│   └── Effect: Detects post-exploitation, can be evaded with LOLBins
├── Security Awareness Training
│   └── Effect: Reduces phishing success, but not eliminated
├── PowerShell Logging
│   └── Effect: Provides visibility, but may not prevent execution
├── Password Policies (Complexity, Rotation)
│   └── Effect: Reduces spray success, but not eliminated
└── Patch Management
    └── Effect: Reduces exploit opportunities, but legacy systems remain

WEAK OBSTACLES (Low Effectiveness)
├── Traditional Antivirus
│   └── Effect: Bypassed by obfuscation, LOLBins, fileless malware
├── Perimeter Firewall (without inspection)
│   └── Effect: Allows HTTPS C2, VPN tunneling
├── Basic Logging (without SIEM)
│   └── Effect: Data exists but not analyzed for threats
└── Outdated Security Controls
    └── Effect: Signature-based, easily bypassed
```

**APT33 Obstacle Bypasses:**

| Obstacle | APT33 Bypass Technique | Effectiveness |
|----------|------------------------|---------------|
| MFA | Not directly bypassed; targets MFA-exempt services or phishing OTP | Partial |
| Email Security | Polymorphic docs, credential phishing (no malware) | High |
| EDR | Living-off-the-land (PowerShell, WMI, certutil) | High |
| Network Segmentation | Credential theft to cross segments | Medium-High |
| Antivirus | Obfuscation, encoding, legitimate tools | Very High |

#### 2.1.5 Cover and Concealment

**APT33 Concealment Techniques:**

1. **Blending with Normal Activity**
   - Operations during business hours (Iranian time = US/Saudi working hours)
   - Use of legitimate administrative tools (PowerShell, WMI, net commands)
   - C2 traffic to compromised legitimate sites (WordPress blogs)
   - Low-and-slow pace (avoid rate-based detections)

2. **Encrypted/Obfuscated Communications**
   - HTTPS for C2 traffic (encrypted)
   - Base64 encoding of PowerShell commands
   - DNS tunneling for exfiltration (low-profile)
   - Encrypted archives with common tools (WinRAR, 7-Zip)

3. **Anti-Forensics**
   - Log deletion (Windows Event Logs)
   - Timestomping (modify file timestamps)
   - Memory-resident implants (fileless malware)
   - Use of legitimate credentials (appear as authorized users)

4. **Infrastructure Obfuscation**
   - Multi-tier proxy chains (victim → compromised site → VPS → C2)
   - Frequently rotated infrastructure (60-90 day lifespan)
   - Use of privacy-protected domain registration
   - Hosting in permissive jurisdictions

**Defender Counter-Concealment Capabilities:**

- **Behavioral Analytics:** Detect anomalous activity patterns despite legitimate tools
- **Memory Forensics:** Identify fileless malware, injected code
- **Network Traffic Analysis:** Identify beaconing patterns, data exfiltration
- **Deception Technology:** Honeypots, honey tokens trigger on unauthorized access
- **Threat Hunting:** Proactive searches for TTPs, not signatures

### 2.2 Environmental Effects on Operations

#### 2.2.1 Effect on APT33 Operations

**FAVORABLE CONDITIONS:**
- Geopolitical tensions increase operational mandate and resources
- Targets with weak security posture (no MFA, limited logging)
- Widespread use of VPN/webmail (large attack surface)
- Slow threat intelligence sharing (delayed defensive response)
- Weekend/holiday periods (reduced SOC staffing)

**UNFAVORABLE CONDITIONS:**
- Heightened alert state (post-incident, post-public reporting)
- MFA enforcement across remote access
- Mature threat hunting programs
- Segmented networks with strict access controls
- Law enforcement / intelligence disruption operations

#### 2.2.2 Effect on Defensive Operations

**FAVORABLE CONDITIONS:**
- Intelligence sharing (sector-specific ISACs)
- Mature security tooling (SIEM, EDR, SOAR)
- Security-aware workforce (training programs)
- Zero Trust architecture implementation
- Threat intelligence feeds (IOC, TTP updates)

**UNFAVORABLE CONDITIONS:**
- Legacy systems (difficult to patch, monitor)
- Flat networks (no segmentation)
- Limited security budget/staffing
- Cloud migration (expanding attack surface, visibility gaps)
- Third-party/supply chain risks

### 2.3 Critical Windows of Vulnerability

**APT33 Operational Windows:**

```
WINDOW 1: INITIAL ACCESS (Days 1-30)
├── Vulnerability: User interaction (phishing), weak passwords
├── Detection Opportunity: Email security, auth anomalies
├── Defender Action: Block execution, revoke credentials
└── If Missed: Adversary establishes foothold

WINDOW 2: PRIVILEGE ESCALATION (Days 1-14)
├── Vulnerability: Weak credential storage, misconfigurations
├── Detection Opportunity: LSASS access, unusual process activity
├── Defender Action: Isolate host, reset credentials
└── If Missed: Adversary obtains domain admin

WINDOW 3: LATERAL MOVEMENT (Days 7-60)
├── Vulnerability: Weak segmentation, shared credentials
├── Detection Opportunity: Unusual authentication patterns, SMB/RDP
├── Defender Action: Segment network, revoke credentials
└── If Missed: Adversary accesses critical systems

WINDOW 4: DATA EXFILTRATION (Days 30-90+)
├── Vulnerability: Lack of DLP, large data transfers not monitored
├── Detection Opportunity: Large uploads, DNS anomalies
├── Defender Action: Block egress, isolate systems
└── If Missed: Mission success for adversary
```

**Defender Decision Points:**

| Detection Point | Decision Time | Recommended Action |
|----------------|---------------|-------------------|
| Phishing email detected | Minutes-Hours | Block sender, warn users, hunt for clicks |
| Suspicious authentication | Hours | Investigate user, verify legitimacy, consider revocation |
| Malware execution | Minutes-Hours | Isolate host, contain spread, begin forensics |
| LSASS access / Mimikatz | Minutes | Isolate host, reset all credentials, hunt for lateral movement |
| Lateral movement detected | Hours | Segment network, revoke credentials, hunt for additional compromises |
| Data staging/exfil | Minutes-Hours | Block egress, identify data, assess impact |

---

## Step 3: Evaluate the Adversary

### 3.1 Adversary Composition and Disposition

#### 3.1.1 Organization Structure

```
APT33 ORGANIZATIONAL STRUCTURE (ASSESSED)

┌─────────────────────────────────────────────────────────────┐
│          IRANIAN GOVERNMENT LEADERSHIP                       │
│          (Strategic Direction & Tasking)                     │
└────────────────────┬────────────────────────────────────────┘
                     │
          ┌──────────┴──────────┐
          │                     │
┌─────────▼──────────┐   ┌─────▼──────────────┐
│  IRGC / MOIS       │   │  Ministry of ICT   │
│  (Oversight)       │   │  (Infrastructure)  │
└─────────┬──────────┘   └────────────────────┘
          │
          │
┌─────────▼───────────────────────────────────────────┐
│              APT33 OPERATIONAL UNIT                  │
│         (Estimated 20-50 personnel)                  │
├──────────────────────────────────────────────────────┤
│                                                      │
│  ┌────────────┐  ┌────────────┐  ┌──────────────┐  │
│  │ MANAGEMENT │  │ TARGETING  │  │ INTELLIGENCE │  │
│  │ (3-5 ppl)  │  │ (2-3 ppl)  │  │ (2-4 ppl)    │  │
│  └────────────┘  └────────────┘  └──────────────┘  │
│                                                      │
│  ┌────────────┐  ┌────────────┐  ┌──────────────┐  │
│  │ OPERATORS  │  │ DEVELOPERS │  │ INFRA TEAM   │  │
│  │ (8-12 ppl) │  │ (3-6 ppl)  │  │ (2-4 ppl)    │  │
│  └────────────┘  └────────────┘  └──────────────┘  │
│                                                      │
└──────────────────────────────────────────────────────┘
```

**Role Descriptions:**

1. **Management (3-5 personnel)**
   - Strategic planning and coordination
   - Reporting to government leadership
   - Resource allocation
   - Operational security oversight

2. **Targeting Team (2-3 personnel)**
   - Target selection based on strategic requirements
   - Reconnaissance and target profiling
   - Victim prioritization
   - Success metrics tracking

3. **Intelligence Analysis (2-4 personnel)**
   - Defensive capability assessment
   - TTPs effectiveness analysis
   - Threat intelligence monitoring (tracking defender publications)
   - Competitive intelligence (other APT groups)

4. **Operators (8-12 personnel)**
   - Hands-on-keyboard operations
   - Initial access execution
   - Post-exploitation activities
   - Data exfiltration
   - 24/7 coverage unlikely (business hours primarily)

5. **Developers (3-6 personnel)**
   - Custom malware development (TURNEDUP, DEADWOOD, SHAPESHIFT)
   - Tool modification (PowerSploit, Mimikatz)
   - Obfuscation techniques
   - Exploit development/adaptation

6. **Infrastructure Team (2-4 personnel)**
   - C2 infrastructure setup and maintenance
   - Domain/server acquisition
   - Operational security for infrastructure
   - Infrastructure rotation

#### 3.1.2 Capabilities Assessment

**TECHNICAL CAPABILITIES:**

| Capability Area | Rating | Evidence |
|----------------|--------|----------|
| **Custom Malware Development** | MEDIUM-HIGH | Multiple custom tools (TURNEDUP, DEADWOOD, SHAPESHIFT, POWERTON) |
| **Exploit Development** | MEDIUM | Uses publicly-known exploits, limited 0-day capability |
| **Social Engineering** | MEDIUM-HIGH | Effective spearphishing campaigns, credential harvesting |
| **Operational Security** | MEDIUM | Moderate OPSEC, reuses infrastructure, detectable patterns |
| **Network Exploitation** | MEDIUM-HIGH | Effective lateral movement, credential dumping |
| **Persistence Mechanisms** | MEDIUM | Standard techniques, not particularly sophisticated |
| **Anti-Forensics** | MEDIUM | Log deletion, timestomping, some obfuscation |
| **Encryption/Obfuscation** | MEDIUM | Base64, XOR, standard encryption tools |
| **C2 Infrastructure** | MEDIUM-HIGH | Multi-tier proxies, compromised infrastructure use |
| **Living-off-the-Land** | HIGH | Extensive use of PowerShell, WMI, native tools |

**OPERATIONAL CAPABILITIES:**

| Capability | Effectiveness | Constraints |
|-----------|---------------|-------------|
| **Initial Access (Spearphishing)** | HIGH | Dependent on user interaction, increasingly detected |
| **Initial Access (Password Spraying)** | MEDIUM | MFA adoption reducing effectiveness |
| **Privilege Escalation** | HIGH | Effective credential dumping, token manipulation |
| **Lateral Movement** | HIGH | Skilled at exploiting trust relationships |
| **Data Exfiltration** | MEDIUM-HIGH | Effective staging and exfil, but detectable with proper monitoring |
| **Destructive Actions** | MEDIUM | Demonstrated capability (SHAPESHIFT), but rarely employed |
| **Long-term Persistence** | MEDIUM | Can maintain access, but often detected within 90-180 days |

**RESOURCE AVAILABILITY:**

- **Financial:** MEDIUM-HIGH (state-sponsored, sustained operations)
- **Personnel:** MEDIUM (estimated 20-50 dedicated personnel)
- **Time:** HIGH (patient, campaigns lasting months)
- **Infrastructure:** MEDIUM-HIGH (ability to acquire and rotate infrastructure)
- **Technical Resources:** MEDIUM (commercial tools, open-source frameworks, limited custom development)

#### 3.1.3 Adversary Doctrine and Tactics

**OPERATIONAL DOCTRINE:**

APT33 operates under Iranian cyber doctrine emphasizing:

1. **Strategic Patience**
   - Long-term campaigns (3-9 months typical)
   - Willingness to wait for high-value access
   - Persistent re-targeting of failed objectives

2. **Blended Operations**
   - Mix of espionage and potential destructive capability
   - Espionage primary, destruction held in reserve
   - Coordinate with other Iranian APT groups (APT34, APT35)

3. **Sector Specialization**
   - Deep focus on aviation and energy
   - Institutional knowledge of target environments
   - Reuse of proven TTPs within sectors

4. **Risk-Managed Aggression**
   - Espionage operations: Moderate OPSEC, some detection acceptable
   - Destructive operations: Reserved for high-value strategic objectives
   - Avoid attribution when possible, but not at all costs

**TACTICAL PREFERENCES:**

```
PHASE          PREFERRED TTPs                          ALTERNATIVE TTPs
────────────────────────────────────────────────────────────────────────
INITIAL        1. Spearphishing (macro docs)          1. Password spraying
ACCESS         2. Credential harvesting               2. Web app exploitation
               3. Valid account compromise            3. Supply chain access

EXECUTION      1. PowerShell                          1. VBScript
               2. Malicious Office macros             2. Scripting (WScript, CScript)
               3. Living-off-the-land binaries        3. Custom malware execution

PERSISTENCE    1. Scheduled tasks                     1. Registry Run keys
               2. Create local accounts               2. WMI event subscriptions
               3. Backdoor accounts                   3. Service creation

PRIVILEGE      1. LSASS credential dumping (Mimikatz) 1. Token manipulation
ESCALATION     2. Cached credential extraction        2. Exploit for privesc
               3. Registry SAM dumping                3. Password spraying elevate

DEFENSE        1. Obfuscation (Base64, encoding)      1. Log deletion
EVASION        2. Living-off-the-land tools           2. Timestomping
               3. Encrypted/packed payloads           3. Rundll32/regsvr32 proxy exec

CREDENTIAL     1. LSASS memory dumping                1. Browser credential theft
ACCESS         2. Registry credential extraction      2. Keystroke logging
               3. GPP password extraction             3. Network sniffing (credentials)

DISCOVERY      1. Active Directory enumeration        1. Network scanning
               2. Account/group enumeration (net)     2. System information gathering
               3. Share enumeration                   3. Process/service enumeration

LATERAL        1. Pass-the-hash                       1. Remote Desktop Protocol
MOVEMENT       2. RDP with compromised credentials    2. WMI remote execution
               3. PsExec-style service execution      3. PowerShell remoting

COLLECTION     1. Archive sensitive files (RAR, 7z)  1. Screen capture
               2. Email collection                    2. Keylogging
               3. Document theft                      3. Clipboard monitoring

COMMAND &      1. HTTP/HTTPS to compromised sites     1. DNS tunneling
CONTROL        2. Multi-tier proxy infrastructure     2. Custom TCP/UDP protocols
               3. Beaconing patterns                  3. Cloud services (Dropbox, etc.)

EXFILTRATION   1. C2 channel exfiltration            1. DNS exfiltration
               2. Encrypted archives                  2. Cloud storage upload
               3. Large transfers over HTTPS          3. Webmail attachment
```

#### 3.1.4 Recent Activity and Trends

**2023-2025 OPERATIONAL SHIFTS:**

1. **Increased Cloud Targeting**
   - More focus on Office 365, Azure
   - OAuth token theft techniques
   - Cloud-native persistence methods

2. **Adaptation to MFA**
   - Targeting MFA-exempt services
   - OTP phishing attempts (limited success)
   - Focus on initial access before MFA widely deployed

3. **Living-off-the-Land Emphasis**
   - Reduced custom malware use
   - Increased PowerShell, WMI, certutil
   - Blending with legitimate admin activity

4. **Infrastructure Sophistication**
   - More frequent rotation (60-day average)
   - Better operational security
   - Use of bulletproof hosting providers

5. **Supply Chain Interest**
   - Targeting IT service providers
   - MSP compromise for customer access
   - Third-party vendor exploitation

### 3.2 Adversary Strength Assessment

**QUANTITATIVE ASSESSMENT:**

```
CAPABILITY DIMENSION          RATING (1-10)    NOTES
──────────────────────────────────────────────────────────────────
Technical Sophistication           6.5         Custom malware, but not cutting-edge
Human Intelligence                 7.0         Effective targeting, social engineering
Financial Resources                7.5         State-sponsored, sustained funding
Operational Security               6.0         Moderate OPSEC, detectable patterns
Persistence & Determination        8.5         Patient, re-targets failed objectives
Adaptability                       7.0         Evolves TTPs based on defenses
Speed of Operations                6.0         Methodical, not rapid
Scale of Operations                6.5         Multiple simultaneous campaigns
──────────────────────────────────────────────────────────────────
OVERALL THREAT CAPABILITY          7.0/10      MEDIUM-HIGH THREAT
```

**COMPARATIVE ANALYSIS:**

| Attribute | APT33 | APT29 (Russia) | APT1 (China) | APT38 (N. Korea) |
|-----------|-------|----------------|--------------|------------------|
| Technical Skill | Medium-High | Very High | Medium | Medium-High |
| Stealth | Medium | Very High | Medium | Low-Medium |
| Resources | High | Very High | Very High | Medium |
| Target Focus | Narrow (Aviation/Energy) | Broad (Government/Defense) | Broad (IP Theft) | Narrow (Financial) |
| Persistence | Very High | High | Medium | Medium |
| Destructive Capability | Medium (Reserved) | Low (Espionage focus) | Low (Espionage focus) | High (Mission-critical) |

**RELATIVE STRENGTHS:**
- Sector-specific expertise (aviation, energy)
- Persistent targeting over long periods
- Willingness to invest time in difficult targets
- Credential harvesting and lateral movement skills
- Living-off-the-land techniques

**RELATIVE WEAKNESSES:**
- Moderate operational security (detectable patterns)
- Limited zero-day exploitation capability
- Reuse of infrastructure (enables tracking)
- Predictable operational hours (Iranian timezone)
- Limited effectiveness against mature defenders with MFA

### 3.3 Adversary Vulnerabilities

**TECHNICAL VULNERABILITIES:**

1. **Infrastructure Reuse**
   - **Vulnerability:** Domains/IPs reused across campaigns
   - **Exploitation:** Threat intelligence sharing, blocking
   - **Impact:** Force infrastructure rotation, increase costs

2. **Predictable TTPs**
   - **Vulnerability:** Consistent use of Mimikatz, PowerShell patterns
   - **Exploitation:** Signature-based and behavioral detection
   - **Impact:** Early detection, containment

3. **Operational Timing**
   - **Vulnerability:** Activity during Iranian business hours
   - **Exploitation:** Temporal analysis, anomaly detection
   - **Impact:** Attribution confidence, detection

4. **Tool Artifacts**
   - **Vulnerability:** Farsi language strings, compilation timestamps
   - **Exploitation:** Attribution, malware analysis
   - **Impact:** Strategic intelligence, attribution

**OPERATIONAL VULNERABILITIES:**

1. **Initial Access Dependency**
   - **Vulnerability:** Heavy reliance on phishing, password spraying
   - **Exploitation:** MFA enforcement, email security, user training
   - **Impact:** Prevent 60-70% of initial access attempts

2. **Credential Dependency**
   - **Vulnerability:** Operations heavily dependent on stolen credentials
   - **Exploitation:** Credential Guard, PAM, frequent rotation
   - **Impact:** Limit lateral movement, slow operations

3. **Limited Exploit Capability**
   - **Vulnerability:** Relies on public exploits, not 0-days
   - **Exploitation:** Rapid patching, virtual patching
   - **Impact:** Close vulnerability window, force TTP changes

4. **Detection Tolerance**
   - **Vulnerability:** Moderate OPSEC suggests some detection is acceptable
   - **Exploitation:** Aggressive threat hunting, public disclosure
   - **Impact:** Force operational changes, increase costs

**STRATEGIC VULNERABILITIES:**

1. **Geopolitical Isolation**
   - **Vulnerability:** Limited international cooperation
   - **Exploitation:** Law enforcement actions, infrastructure takedowns
   - **Impact:** Disrupt operations, seize infrastructure

2. **Sector Specialization**
   - **Vulnerability:** Deep focus makes TTPs sector-specific and recognizable
   - **Exploitation:** Sector-wide information sharing (ISACs)
   - **Impact:** Coordinated defense, rapid IOC dissemination

3. **Resource Constraints**
   - **Vulnerability:** Not unlimited resources (unlike Russia, China)
   - **Exploitation:** Increase operational costs through defensive hardening
   - **Impact:** Force prioritization, reduce campaign breadth

### 3.4 Adversary Capabilities by Warfighting Function

**MISSION COMMAND:**
- Centralized strategic direction from Iranian government
- Operational autonomy for tactical decisions
- Good coordination within APT33, moderate coordination with other Iranian APTs
- Assessment: **EFFECTIVE**

**MOVEMENT AND MANEUVER:**
- Effective lateral movement within compromised networks
- Good understanding of Windows environments
- Limitations in OT/ICS environments
- Assessment: **EFFECTIVE** (IT), **LIMITED** (OT)

**INTELLIGENCE:**
- Strong target reconnaissance
- Monitors threat intelligence to assess defensive posture
- Limited visibility into most secure environments
- Assessment: **EFFECTIVE**

**FIRES (Offensive Cyber):**
- Primary: Espionage operations (HIGH effectiveness)
- Secondary: Destructive operations (MEDIUM effectiveness, rarely employed)
- Precision: MEDIUM (some collateral impact acceptable)
- Assessment: **EFFECTIVE FOR ESPIONAGE**, **MODERATE FOR DESTRUCTION**

**SUSTAINMENT:**
- Persistent access to resources (state-sponsored)
- Ability to sustain long campaigns (3-9 months)
- Can weather some disruptions (infrastructure takedowns)
- Assessment: **EFFECTIVE**

**PROTECTION:**
- Moderate operational security
- Some anti-forensics capability
- Vulnerable to infrastructure attribution
- Assessment: **MODERATE**

---

## Step 4: Determine Adversary Courses of Action

### 4.1 Adversary Mission Analysis

**APT33 MISSION (Assessed):**

```
STRATEGIC OBJECTIVE:
Collect intelligence on aviation and energy sectors in support of Iranian
strategic interests, including sanctions evasion, competitive advantage,
and potential future destructive operations.

SPECIFIED TASKS:
1. Collect proprietary aerospace technology and designs
2. Obtain energy sector strategic plans and contracts
3. Access executive communications and decision-making
4. Monitor Saudi Arabian aviation/energy activities
5. Maintain persistent access for future tasking
6. (Conditional) Pre-position for destructive operations

IMPLIED TASKS:
1. Maintain operational security to avoid attribution (where feasible)
2. Coordinate with other Iranian APT groups
3. Adapt TTPs to evolving defensive measures
4. Avoid detection that would trigger incident response
5. Comply with Iranian government legal/policy frameworks

MISSION CONSTRAINTS:
1. Limited resources compared to Russian/Chinese APTs
2. Sector specialization (aviation/energy) limits target pool
3. International sanctions limit infrastructure acquisition options
4. Must balance operational tempo with detection risk
5. Geopolitical consequences of destructive operations
```

**COMMANDER'S INTENT (APT33 Leadership - Assessed):**

"Maintain persistent intelligence collection against U.S., Saudi, and South Korean aviation and energy sectors. Prioritize collection of proprietary technology, strategic plans, and decision-maker communications. Avoid detection where feasible, but strategic intelligence collection takes precedence over OPSEC. Be prepared to execute destructive operations on order."

### 4.2 Most Likely Course of Action (MLCOA)

**MLCOA: SUSTAINED ESPIONAGE OPERATIONS**

**Concept of Operations:**

APT33 will conduct sustained espionage operations against aviation and energy sector targets in the United States and Saudi Arabia, prioritizing credential harvesting and persistent access over rapid intelligence collection.

**Detailed COA:**

```
PHASE 1: TARGET DEVELOPMENT (Weeks 1-4)
┌──────────────────────────────────────────────────────────────┐
│ ACTIVITIES:                                                  │
│ • OSINT reconnaissance on target organizations               │
│ • LinkedIn employee profiling (roles, emails)                │
│ • Identify VPN/webmail portals for password spraying         │
│ • Develop spearphishing themes (industry-specific)           │
│ • Acquire/prepare infrastructure (domains, servers)          │
│                                                              │
│ INDICATORS:                                                  │
│ • Increased LinkedIn profile views from Iran/Middle East     │
│ • Domain registrations typosquatting target companies        │
│ • Reconnaissance scanning of target public IPs               │
│ • WHOIS queries on target domains                            │
└──────────────────────────────────────────────────────────────┘

PHASE 2: INITIAL ACCESS (Weeks 4-8)
┌──────────────────────────────────────────────────────────────┐
│ ACTIVITIES:                                                  │
│ • Spearphishing campaign (aviation/energy themes)            │
│ • Password spraying against VPN/webmail (1-3 attempts/user)  │
│ • Credential harvesting via fake login pages                 │
│ • Exploitation of public-facing applications (opportunistic) │
│                                                              │
│ SUCCESS CRITERIA:                                            │
│ • 1-5 successful account compromises OR                      │
│ • 1-2 successful spearphishing infections                    │
│                                                              │
│ INDICATORS:                                                  │
│ • Suspicious emails with aviation/energy themes              │
│ • Failed authentication spikes from external IPs             │
│ • Links to credential harvesting sites                       │
│ • Macro-enabled documents from external senders              │
└──────────────────────────────────────────────────────────────┘

PHASE 3: ESTABLISH FOOTHOLD (Days 1-7 post-compromise)
┌──────────────────────────────────────────────────────────────┐
│ ACTIVITIES:                                                  │
│ • Execute PowerShell downloader (from macro or compromise)   │
│ • Deploy custom backdoor (TURNEDUP, POWERTON)                │
│ • Establish C2 communication (HTTPS to compromised sites)    │
│ • Create persistence (scheduled task, registry)              │
│ • Initial host reconnaissance (whoami, systeminfo, net)      │
│                                                              │
│ INDICATORS:                                                  │
│ • Office apps spawning PowerShell                            │
│ • Suspicious PowerShell with -encodedcommand                 │
│ • Outbound HTTPS to unusual/newly-registered domains         │
│ • Scheduled task creation                                    │
│ • Registry Run key modification                              │
└──────────────────────────────────────────────────────────────┘

PHASE 4: ESCALATE PRIVILEGES (Days 2-14)
┌──────────────────────────────────────────────────────────────┐
│ ACTIVITIES:                                                  │
│ • Credential dumping (Mimikatz, LSASS access)                │
│ • Registry SAM/SECURITY hive dumping                         │
│ • GPP password extraction (if available)                     │
│ • Browser credential theft (Chrome, Firefox)                 │
│ • Search for credential files on disk                        │
│                                                              │
│ SUCCESS CRITERIA:                                            │
│ • Obtain domain admin credentials OR                         │
│ • Multiple privileged account credentials                    │
│                                                              │
│ INDICATORS:                                                  │
│ • LSASS process access by non-system processes               │
│ • Registry hive dumping (reg.exe save)                       │
│ • Access to browser credential files                         │
│ • Mimikatz execution or strings in memory                    │
└──────────────────────────────────────────────────────────────┘

PHASE 5: INTERNAL RECONNAISSANCE (Days 7-30)
┌──────────────────────────────────────────────────────────────┐
│ ACTIVITIES:                                                  │
│ • Active Directory enumeration (net user, PowerView)         │
│ • Network mapping (arp, ipconfig, net view)                  │
│ • File share enumeration (net share, dir)                    │
│ • Identify high-value systems (file servers, email)          │
│ • Map administrator accounts and privileged groups           │
│                                                              │
│ INDICATORS:                                                  │
│ • Rapid succession of "net" commands                         │
│ • PowerShell AD queries (Get-ADUser, Get-ADComputer)         │
│ • File share access from unusual accounts                    │
│ • Port scanning from internal hosts                          │
└──────────────────────────────────────────────────────────────┘

PHASE 6: LATERAL MOVEMENT (Days 14-60)
┌──────────────────────────────────────────────────────────────┐
│ ACTIVITIES:                                                  │
│ • Pass-the-Hash to access additional systems                 │
│ • RDP connections using compromised credentials              │
│ • PsExec-style service execution on targets                  │
│ • Deploy backdoors on key systems (DC, file servers)         │
│ • Establish redundant access points                          │
│                                                              │
│ SUCCESS CRITERIA:                                            │
│ • Access to Domain Controllers                               │
│ • Access to file servers with sensitive data                 │
│ • Access to email infrastructure                             │
│                                                              │
│ INDICATORS:                                                  │
│ • Logon Type 3 (network) from single account to many hosts   │
│ • RDP connections (Type 10) from internal workstations       │
│ • Service installation on remote systems                     │
│ • Unusual authentication patterns                            │
└──────────────────────────────────────────────────────────────┘

PHASE 7: COLLECTION & EXFILTRATION (Days 30-90+)
┌──────────────────────────────────────────────────────────────┐
│ ACTIVITIES:                                                  │
│ • Identify and stage target data (IP, strategic docs)        │
│ • Archive data with WinRAR/7-Zip (password-protected)        │
│ • Exfiltrate via C2 channel (HTTPS)                          │
│ • Maintain persistent access for future tasking              │
│ • Monitor for incident response indicators                   │
│                                                              │
│ SUCCESS CRITERIA:                                            │
│ • Exfiltrate engineering designs, strategic plans            │
│ • Maintain persistent access for 90+ days                    │
│                                                              │
│ INDICATORS:                                                  │
│ • Archive file creation (.rar, .7z, .zip)                    │
│ • Large outbound data transfers                              │
│ • Upload-heavy network connections                           │
│ • DNS tunneling patterns                                     │
└──────────────────────────────────────────────────────────────┘

PHASE 8: MAINTAIN PERSISTENCE (Ongoing)
┌──────────────────────────────────────────────────────────────┐
│ ACTIVITIES:                                                  │
│ • Monitor for defensive actions (AV, credential resets)      │
│ • Adapt C2 infrastructure if detected                        │
│ • Re-compromise if access lost                               │
│ • Deploy additional backdoors/accounts                       │
│ • Coordinate with other Iranian APTs if needed               │
│                                                              │
│ DURATION:                                                    │
│ • Target: 90-180 days before detection                       │
│ • Can extend to 12+ months if undetected                     │
└──────────────────────────────────────────────────────────────┘
```

**MLCOA Assessment:**

| Criteria | Rating | Rationale |
|----------|--------|-----------|
| **Suitability** | HIGH | Aligns with Iranian strategic objectives, proven successful historically |
| **Feasibility** | HIGH | APT33 has demonstrated capabilities for all phases |
| **Acceptability** | HIGH | Acceptable risk level for espionage operations |
| **Distinguishability** | MEDIUM | Specific techniques distinguish from other threat actors |
| **Completeness** | HIGH | Covers all operational phases from initial access to persistence |
| **Probability** | **85%** | Most likely COA based on historical patterns |

### 4.3 Most Dangerous Course of Action (MDCOA)

**MDCOA: DESTRUCTIVE OPERATIONS AGAINST CRITICAL INFRASTRUCTURE**

**Concept of Operations:**

In response to escalating geopolitical tensions or military conflict, APT33 conducts destructive cyber operations against U.S. or Saudi energy infrastructure, aiming to disrupt operations and cause economic damage.

**Detailed COA:**

```
TRIGGER CONDITIONS:
├── Military conflict between Iran and Saudi Arabia/Israel
├── U.S. military action against Iran
├── Severe sanctions escalation
└── Iranian leadership directive for retaliation

PHASE 1: PRE-POSITIONING (Months before trigger)
┌──────────────────────────────────────────────────────────────┐
│ ACTIVITIES:                                                  │
│ • Conduct espionage operations per MLCOA                     │
│ • Identify critical systems (SCADA, safety systems)          │
│ • Map OT/ICS networks and control systems                    │
│ • Pre-position destructive malware (SHAPESHIFT variants)     │
│ • Establish redundant access to critical infrastructure      │
│                                                              │
│ TARGETS:                                                     │
│ • Oil refineries (control systems)                           │
│ • Natural gas facilities                                     │
│ • Power generation facilities                                │
│ • Pipeline SCADA systems                                     │
│ • Airport control systems                                    │
│                                                              │
│ INDICATORS:                                                  │
│ • Reconnaissance of OT/ICS systems                           │
│ • Access to jump servers connecting IT to OT                 │
│ • Unusual interest in SCADA, PLCs, HMIs                      │
│ • Download of destructive malware components                 │
└──────────────────────────────────────────────────────────────┘

PHASE 2: EXECUTION (Upon trigger - Hours to Days)
┌──────────────────────────────────────────────────────────────┐
│ ACTIVITIES:                                                  │
│ • Activate pre-positioned destructive malware                │
│ • Wipe critical IT systems (Active Directory, backups)       │
│ • Disrupt OT systems (if access achieved)                    │
│ • Delete system logs and forensic evidence                   │
│ • Destroy MBR/partitions on critical servers                 │
│                                                              │
│ SHAPESHIFT CAPABILITIES:                                     │
│ • MBR overwrite (render systems unbootable)                  │
│ • File deletion (target-specific file types)                 │
│ • Shadow copy deletion (prevent recovery)                    │
│ • Wiper malware deployment                                   │
│                                                              │
│ EXPECTED IMPACT:                                             │
│ • Days to weeks of IT system disruption                      │
│ • Potential safety system impacts (OT)                       │
│ • Operational shutdown (refineries, pipelines)               │
│ • Economic damage ($10M - $1B+ depending on target)          │
│                                                              │
│ INDICATORS:                                                  │
│ • Simultaneous system failures across organization           │
│ • MBR corruption on multiple systems                         │
│ • Mass file deletion                                         │
│ • Shadow copy deletion commands                              │
│ • SCADA/HMI disruptions                                      │
└──────────────────────────────────────────────────────────────┘

PHASE 3: POST-ATTACK (Days after)
┌──────────────────────────────────────────────────────────────┐
│ ACTIVITIES:                                                  │
│ • Monitor for attribution and response                       │
│ • Potential additional strikes if directed                   │
│ • Shift to other targets to maintain pressure                │
│ • Information operations (amplify impact messaging)          │
│                                                              │
│ STRATEGIC OBJECTIVES:                                        │
│ • Demonstrate capability and resolve                         │
│ • Impose economic costs on adversaries                       │
│ • Deter future actions against Iran                          │
│ • Signal Iranian cyber power                                 │
└──────────────────────────────────────────────────────────────┘
```

**MDCOA Assessment:**

| Criteria | Rating | Rationale |
|----------|--------|-----------|
| **Suitability** | MEDIUM | Achieves strategic objectives in conflict scenario |
| **Feasibility** | MEDIUM | APT33 has destructive tools but limited OT/ICS experience |
| **Acceptability** | LOW | High geopolitical risk, potential for escalation |
| **Distinguishability** | HIGH | Destructive operations very distinguishable from espionage |
| **Completeness** | MEDIUM | Requires extensive pre-positioning, uncertain success |
| **Probability** | **15%** | Low probability absent major geopolitical trigger |

**THREAT LEVEL:**
- **Current (Peacetime):** MEDIUM (capability exists, intent low)
- **Heightened Tensions:** HIGH (pre-positioning likely)
- **Active Conflict:** CRITICAL (execution highly likely)

### 4.4 Other Likely Courses of Action

**COA 3: SUPPLY CHAIN COMPROMISE**

**Probability:** 10%
**Concept:** Compromise IT service providers or software vendors to gain access to multiple aviation/energy customers simultaneously.

**Advantages:**
- Access to multiple target organizations
- Leverage trusted relationships
- Difficult to detect (authorized vendor access)

**Disadvantages:**
- Requires significant effort to compromise vendor
- Higher risk of detection (broader impact)
- Limited APT33 historical precedent

**COA 4: MOBILE DEVICE TARGETING**

**Probability:** 5%
**Concept:** Target mobile devices of executives and engineers through malicious apps, SMS phishing, or mobile exploits.

**Advantages:**
- Less mature defenses on mobile platforms
- Access to communications and credentials
- Bypass traditional network defenses

**Disadvantages:**
- Limited APT33 demonstrated capability
- Requires different skill set (mobile exploitation)
- Lower data exfiltration capacity

**COA 5: CLOUD-NATIVE OPERATIONS**

**Probability:** 10%
**Concept:** Focus operations entirely on cloud environments (Office 365, AWS, Azure), avoiding on-premise networks.

**Advantages:**
- Cloud adoption expanding attack surface
- Limited visibility for many organizations
- Easier credential theft (password spray O365)

**Disadvantages:**
- Requires adaptation to cloud TTPs
- MFA more prevalent in cloud
- Less access to on-premise sensitive data

### 4.5 Course of Action Comparison

| COA | Probability | Impact | Detection Risk | Resource Cost | Overall Threat |
|-----|-------------|--------|----------------|---------------|----------------|
| **MLCOA: Sustained Espionage** | 85% | HIGH | MEDIUM | MEDIUM | **CRITICAL** |
| **MDCOA: Destructive Ops** | 15% | VERY HIGH | HIGH | HIGH | **HIGH** (conditional) |
| COA 3: Supply Chain | 10% | HIGH | LOW | VERY HIGH | MEDIUM |
| COA 4: Mobile Targeting | 5% | MEDIUM | MEDIUM | MEDIUM | LOW |
| COA 5: Cloud-Native | 10% | MEDIUM-HIGH | MEDIUM | MEDIUM | MEDIUM |

### 4.6 Decision Points and Indicators

**DECISION POINTS FOR APT33:**

```
DP 1: TARGET SELECTION
├── Trigger: Tasking from Iranian leadership
├── Decision: Which organization(s) to target
├── Indicators: OSINT activity, reconnaissance scanning
└── Defender Action: Monitor for reconnaissance, deception

DP 2: INITIAL ACCESS METHOD
├── Trigger: Target profiling complete
├── Decision: Spearphishing vs. password spray vs. exploit
├── Indicators: Phishing emails, auth failures, scanning
└── Defender Action: Email security, MFA, patching

DP 3: ESCALATE OR PIVOT
├── Trigger: Initial foothold established
├── Decision: Escalate privileges or pivot to other hosts
├── Indicators: LSASS access, lateral movement
└── Defender Action: Credential protection, segmentation

DP 4: EXPAND OR CONSOLIDATE
├── Trigger: Privileged access obtained
├── Decision: Lateral movement or maintain low profile
├── Indicators: Unusual authentication, service execution
└── Defender Action: Anomaly detection, threat hunting

DP 5: EXFILTRATE OR PERSIST
├── Trigger: Target data identified
├── Decision: Exfiltrate now or maintain long-term access
├── Indicators: Data staging, large transfers
└── Defender Action: DLP, network monitoring

DP 6: ABORT OR CONTINUE
├── Trigger: Detection indicators observed
├── Decision: Abandon operation or adapt and continue
├── Indicators: Incident response activities
└── Defender Action: Rapid containment, coordination
```

**INTELLIGENCE INDICATORS AND WARNINGS:**

| Indicator Level | Description | Timeline | Recommended Action |
|----------------|-------------|----------|-------------------|
| **INDICATIONS (I-1)** | OSINT reconnaissance, infrastructure setup | Weeks-Months | Heightened monitoring |
| **WARNING (W-1)** | Spearphishing/password spray attempts | Days-Weeks | Enhance email security, alert users |
| **WARNING (W-2)** | Compromise confirmed (IOCs detected) | Hours-Days | Activate IR, contain compromise |
| **WARNING (W-3)** | Privilege escalation / lateral movement | Hours-Days | Full containment, credential reset |
| **IMMINENT (W-4)** | Data staging, pre-destruction indicators | Hours | Emergency response, isolate systems |
| **ATTACK (W-5)** | Active data exfiltration or destruction | Real-time | Full defensive measures, law enforcement |

---

## Step 5: Intelligence Gaps and Collection Requirements

### 5.1 Priority Intelligence Requirements (PIRs)

**PIR 1: What are APT33's current operational targets?**
- Specific organizations under active targeting
- Sector priorities (aviation vs. energy allocation)
- Geographic focus shifts
- **Collection Methods:** Network traffic analysis, threat intelligence sharing, honeypots

**PIR 2: What are APT33's destructive operation plans and triggers?**
- Pre-positioned destructive malware locations
- Trigger conditions for destructive operations
- Target prioritization for destruction
- **Collection Methods:** Adversary infrastructure monitoring, insider reporting, signals intelligence

**PIR 3: What is APT33's capability against OT/ICS systems?**
- OT-specific tools and expertise
- Previous OT compromises (if any)
- Partnerships with OT-focused threat actors
- **Collection Methods:** Malware analysis, threat intelligence, OT security community reporting

**PIR 4: How is APT33 adapting to MFA and modern defenses?**
- New initial access techniques
- MFA bypass methods
- Cloud-native TTPs
- **Collection Methods:** Incident reports, threat hunting, deception technology

**PIR 5: What is the relationship between APT33 and other Iranian APTs?**
- Operational coordination (APT34, APT35, APT39)
- Access sharing arrangements
- Division of labor by sector
- **Collection Methods:** Infrastructure overlap analysis, TTP correlation, malware code comparison

### 5.2 Information Gaps

**CRITICAL GAPS:**
1. Current APT33 target list and prioritization
2. Destructive capability readiness and deployment plans
3. OT/ICS exploitation capabilities
4. Coordination with other Iranian APTs
5. Supply chain targeting plans

**IMPORTANT GAPS:**
1. Mobile exploitation capabilities
2. Zero-day exploit inventory (if any)
3. Cloud-native TTP evolution
4. Decision-making process for escalation
5. Attribution tolerance and operational security priorities

**USEFUL GAPS:**
1. Personnel composition and organizational structure
2. Budget and resource constraints
3. Training and skill development programs
4. Relationship with Iranian government leadership
5. Long-term strategic objectives (5-10 year horizon)

### 5.3 Collection Requirements

**REQUIREMENT 1: NETWORK-BASED COLLECTION**
- Deploy network sensors in target sectors (aviation, energy)
- Monitor for APT33 IOCs and TTPs
- Establish industry-wide threat intelligence sharing
- **Responsible Entities:** ISACs, security vendors, government agencies

**REQUIREMENT 2: ENDPOINT TELEMETRY**
- Enhanced EDR deployment in high-value targets
- Memory forensics for fileless malware detection
- PowerShell and WMI logging
- **Responsible Entities:** Private sector, security vendors

**REQUIREMENT 3: THREAT INFRASTRUCTURE MONITORING**
- Track known APT33 C2 infrastructure
- Monitor domain registrations (typosquatting, themes)
- Identify new infrastructure through pivoting
- **Responsible Entities:** Threat intelligence firms, government agencies

**REQUIREMENT 4: ADVERSARY CAPABILITY ASSESSMENT**
- Malware reverse engineering (new samples)
- TTP documentation from incidents
- Capability demonstrations (honeypots)
- **Responsible Entities:** Malware analysis labs, honeypot operators

**REQUIREMENT 5: STRATEGIC INTELLIGENCE**
- Iranian cyber policy and doctrine
- Geopolitical factors influencing operations
- Relationships between cyber units
- **Responsible Entities:** Government intelligence agencies

### 5.4 Assumptions and Constraints

**ASSUMPTIONS:**
1. APT33 will continue to prioritize aviation and energy sectors
2. Iranian geopolitical objectives remain consistent (anti-Saudi, anti-U.S.)
3. APT33 has state-level resourcing and support
4. Espionage remains primary mission; destruction is contingency
5. APT33 will adapt TTPs to evolving defenses but maintain core methodologies

**CONSTRAINTS:**
1. Limited intelligence on Iranian government internal decision-making
2. Attribution challenges (Iran uses multiple APT groups)
3. Infrastructure in permissive jurisdictions (difficult takedowns)
4. Encryption limits visibility into C2 communications
5. Legal and policy constraints on defensive cyber operations

---

## Step 6: Recommended Actions

### 6.1 Immediate Actions (72 Hours)

**DEFEND:**
1. **Verify MFA Coverage**
   - Audit all remote access (VPN, webmail, O365)
   - Identify gaps and implement MFA immediately
   - Priority: Aviation and energy sector organizations

2. **Email Security Posture**
   - Enable sandbox for all attachments
   - Block macros from internet-sourced documents
   - Deploy link rewriting and detonation

3. **Hunt for Existing Compromises**
   - Search for APT33 IOCs in logs (see Appendix A)
   - Check for LSASS access events
   - Review authentication anomalies (failed logins, unusual times)

4. **Activate Communication Plans**
   - Alert security operations teams
   - Notify executives of threat
   - Coordinate with sector-specific ISACs

**DETECT:**
5. **Deploy Detection Rules**
   - Implement Sigma/YARA rules (see Appendix B)
   - Configure alerts for high-priority techniques
   - Tune thresholds to reduce false positives

6. **Enhance Logging**
   - Enable PowerShell script block logging
   - Configure Sysmon (if not present)
   - Ensure 90-day log retention minimum

**PREPARE:**
7. **Incident Response Readiness**
   - Review IR playbooks for nation-state actors
   - Identify IR retainer firms
   - Pre-position forensic tools and licenses

8. **Backup Verification**
   - Verify backups are offline and tested
   - Document recovery procedures
   - Identify critical systems for prioritization

### 6.2 Short-Term Actions (30 Days)

**HARDEN:**
1. **Credential Protection**
   - Deploy Credential Guard on Windows 10+
   - Enable LSASS protection (RunAsPPL)
   - Implement LAPS for local admin passwords

2. **Endpoint Hardening**
   - Enable Attack Surface Reduction rules
   - Deploy application whitelisting where feasible
   - Constrained PowerShell language mode for standard users

3. **Network Segmentation**
   - Segment OT from IT networks (if applicable)
   - Implement VLANs for critical assets
   - Deploy internal firewalls

**DETECT:**
4. **Threat Hunting Program**
   - Conduct hypothesis-driven hunts for APT33 TTPs
   - Baseline normal activity for anomaly detection
   - Document findings and improve detections

5. **Deception Technology**
   - Deploy honeypot accounts (privileged-looking names)
   - Create honey tokens (fake credentials in files)
   - Canary systems (fake high-value servers)

**RESPOND:**
6. **Tabletop Exercises**
   - Conduct APT33 scenario tabletop
   - Test communication and escalation procedures
   - Identify gaps in response capabilities

7. **Establish Forensic Capabilities**
   - Train staff on memory forensics
   - Acquire forensic tools (Volatility, Redline)
   - Document evidence preservation procedures

### 6.3 Long-Term Actions (90+ Days)

**TRANSFORM:**
1. **Zero Trust Architecture**
   - Implement continuous authentication
   - Deploy micro-segmentation
   - Enforce least-privilege access

2. **Threat Intelligence Program**
   - Subscribe to commercial TI feeds (APT33 focus)
   - Join Aviation ISAC / Energy ISAC
   - Develop internal TI capability

3. **Security Awareness Evolution**
   - Conduct APT33-specific phishing simulations
   - Train employees on spearphishing recognition
   - Establish security champion program

4. **Advanced Detection**
   - Deploy UEBA for anomaly detection
   - Implement network traffic analysis (NTA)
   - Machine learning-based detection

5. **Supply Chain Security**
   - Assess third-party vendor security posture
   - Implement vendor access monitoring
   - Require MFA for all vendor access

**COLLABORATE:**
6. **Industry Partnerships**
   - Participate in threat intelligence sharing
   - Coordinate defensive measures with peers
   - Share lessons learned from incidents

7. **Government Coordination**
   - Engage with FBI, CISA for threat briefings
   - Report APT33 activity for broader awareness
   - Participate in sector-specific information sharing

### 6.4 Decision Matrix for Defensive Posture

| Threat Level | Indicators | Defensive Posture | Actions |
|--------------|-----------|------------------|---------|
| **LOW** | No specific threats | Normal operations | Standard monitoring, routine hunts |
| **GUARDED** | General Iranian threat reporting | Enhanced monitoring | Increase log review, verify controls |
| **ELEVATED** | APT33 campaign reporting in sector | Heightened alert | Deploy additional detections, hunt actively |
| **HIGH** | Targeting of similar organizations | Active defense | 24/7 SOC, aggressive hunting, limit access |
| **SEVERE** | Confirmed compromise or attempt | Maximum defense | IR activation, isolation, full forensics |

### 6.5 Metrics for Success

**DEFENSIVE EFFECTIVENESS METRICS:**
1. Time to detect APT33 compromise (target: <24 hours)
2. Time to contain after detection (target: <4 hours)
3. Percentage of endpoints with EDR (target: 100%)
4. MFA coverage for remote access (target: 100%)
5. Threat hunting cadence (target: weekly)
6. Phishing simulation click rate (target: <5%)
7. Mean time to patch critical vulnerabilities (target: <14 days)

**INTELLIGENCE EFFECTIVENESS METRICS:**
1. IOC coverage in defensive tools (target: 100% within 24 hours of publication)
2. TTP detection rule coverage (target: 80% of MITRE techniques)
3. Time from incident to TI product (target: <48 hours)
4. Intelligence sharing participation (target: monthly contributions)

---

## Appendices

### Appendix A: Indicators of Compromise (IOCs)

**FILE HASHES (SHA256) - SAMPLE:**
```
TURNEDUP Backdoor:
bc69a24a06e2b4bfaeb1e4a7a4a4e1a3d3c4f5e6d7e8f9a0b1c2d3e4f5a6b7c8

DEADWOOD Dropper:
7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8

SHAPESHIFT Wiper:
a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2

(NOTE: Hashes change frequently due to recompilation. See threat intelligence feeds for current hashes.)
```

**NETWORK INDICATORS:**
```
C2 DOMAINS (Historical - likely rotated):
aviation-maintenance[.]com
secure-aerospace[.]com
energy-portal[.]net
*-login[.]tk
*-update[.]ml

C2 IP ADDRESSES (Historical):
185.141.25.0/24
89.108.83.0/24
5.39.217.0/24

MALICIOUS EMAIL DOMAINS:
aeroservice[.]net
aerospace-inc[.]com
oil-services[.]net
```

**HOST-BASED INDICATORS:**
```
REGISTRY KEYS:
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate
HKLM\Software\Microsoft\Windows\CurrentVersion\Run\SystemMaintenance

FILE PATHS:
%TEMP%\~tmp*.exe
C:\Users\Public\*.exe
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk

SCHEDULED TASKS:
GoogleUpdateTask
AdobeUpdate
WindowsDefenderUpdate (fake)

MUTEX NAMES:
Global\{8F6F0AC4-B9A1-45fd-A8CF-72FE4C1234AB}
```

### Appendix B: Detection Rules

**SIGMA RULES (Sample):**

```yaml
# PowerShell Download Cradle
title: APT33 PowerShell Download Cradle
status: stable
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains|all:
      - 'IEX'
      - 'Net.WebClient'
      - 'DownloadString'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001

# LSASS Access
title: APT33 Credential Dumping via LSASS Access
status: stable
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess: '0x1F0FFF'
  filter:
    SourceImage|endswith:
      - '\csrss.exe'
      - '\wininit.exe'
      - '\winlogon.exe'
  condition: selection and not filter
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001
```

### Appendix C: MITRE ATT&CK Navigator Layer

*See separate JSON file: APT33_ATTACK_Navigator_Layer.json*

### Appendix D: Glossary

| Term | Definition |
|------|------------|
| **AOI** | Area of Interest - geographic/cyber region of intelligence concern |
| **AO** | Area of Operations - where defender operations occur |
| **COA** | Course of Action - adversary operational approach |
| **IPB** | Intelligence Preparation of the Battlefield |
| **MDCOA** | Most Dangerous Course of Action |
| **MLCOA** | Most Likely Course of Action |
| **NAI** | Named Area of Interest - specific target area |
| **PIR** | Priority Intelligence Requirement |
| **TAEC** | Targeted Asset Evaluation Criteria |
| **TTPs** | Tactics, Techniques, and Procedures |

### Appendix E: References

1. FireEye (2017): "APT33: Insights into Iranian Cyber Espionage"
2. Symantec (2019): "Elfin: Relentless Espionage Group"
3. Microsoft (2023): "Peach Sandstorm Activity Report"
4. MITRE ATT&CK: APT33 Group Profile (G0064)
5. CISA: Iranian Threat Actor Advisory
6. U.S. Army: ATP 2-01.3 Intelligence Preparation of the Battlefield

### Appendix F: Distribution List

- Security Operations Centers (SOC)
- Incident Response Teams
- Threat Intelligence Teams
- Network Security Operations
- Executive Leadership (CISO, CIO)
- Sector ISACs (Aviation ISAC, Energy ISAC)
- Government Partners (FBI, CISA)

---

## Document Control

**Classification:** UNCLASSIFIED // FOR TRAINING USE ONLY
**Version:** 1.0
**Date:** November 6, 2025
**Next Review:** February 6, 2026 (Quarterly)
**Prepared By:** Cyber Intelligence Preparation Team
**Approved By:** [Training Exercise Only - No Approval Required]

**Change Log:**
- v1.0 (2025-11-06): Initial IPB publication

---

**END OF INTELLIGENCE PREPARATION OF THE BATTLEFIELD**

*This IPB is provided for training and educational purposes only. All assessments are based on publicly available threat intelligence and MITRE ATT&CK data. Probability assessments and adversary intentions are intelligence judgments, not certainties.*
