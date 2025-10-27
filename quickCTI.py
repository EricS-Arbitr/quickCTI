"""
MITRE ATT&CK Threat Group STIX Extractor
Fetches STIX 2.0 data for a specific threat actor from MITRE ATT&CK Enterprise
"""

import requests
import json
import sys
import argparse
from datetime import datetime
from typing import Dict, List, Optional

# MITRE ATT&CK Enterprise URL
MITRE_ENTERPRISE_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'

class MITREThreatGroupExtractor:
    """Extract threat group data from MITRE ATT&CK"""
    
    def __init__(self):
        self.attack_data = None
        self.objects_by_id = {}
        
    def fetch_attack_data(self):
        """Download MITRE ATT&CK Enterprise data"""
        print("[*] Fetching MITRE ATT&CK Enterprise data...")
        
        try:
            response = requests.get(MITRE_ENTERPRISE_URL, timeout=60)
            
            if response.status_code == 200:
                self.attack_data = response.json()
                
                # Create lookup dictionary by ID for fast access
                for obj in self.attack_data.get('objects', []):
                    obj_id = obj.get('id')
                    if obj_id:
                        self.objects_by_id[obj_id] = obj
                
                print(f"[+] Successfully fetched {len(self.attack_data['objects'])} STIX objects")
                return True
            else:
                print(f"[-] Failed to fetch data: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            print(f"[-] Error fetching MITRE data: {e}")
            return False
    
    def search_threat_group(self, group_name: str) -> Optional[Dict]:
        """Search for a threat group by name or alias"""
        print(f"\n[*] Searching for threat group: {group_name}")
        
        group_name_lower = group_name.lower()
        
        for obj in self.attack_data.get('objects', []):
            if obj.get('type') == 'intrusion-set':
                # Check name
                name = obj.get('name', '').lower()
                if group_name_lower in name:
                    return obj
                
                # Check aliases
                aliases = obj.get('aliases', [])
                for alias in aliases:
                    if group_name_lower in alias.lower():
                        return obj
        
        return None
    
    def list_all_threat_groups(self) -> List[Dict]:
        """List all available threat groups"""
        groups = []
        
        for obj in self.attack_data.get('objects', []):
            if obj.get('type') == 'intrusion-set':
                groups.append({
                    'name': obj.get('name'),
                    'id': obj.get('id'),
                    'aliases': obj.get('aliases', []),
                    'description': obj.get('description', '')[:100] + '...'
                })
        
        return sorted(groups, key=lambda x: x['name'])
    
    def get_related_techniques(self, group_id: str) -> List[Dict]:
        """Get all techniques used by the threat group"""
        techniques = []
        
        # Find relationships where this group is the source
        for obj in self.attack_data.get('objects', []):
            if obj.get('type') == 'relationship':
                if obj.get('source_ref') == group_id and obj.get('relationship_type') == 'uses':
                    target_id = obj.get('target_ref')
                    
                    # Get the technique details
                    if target_id and target_id.startswith('attack-pattern'):
                        technique = self.objects_by_id.get(target_id)
                        if technique:
                            techniques.append({
                                'technique': technique,
                                'relationship': obj
                            })
        
        return techniques
    
    def get_related_software(self, group_id: str) -> List[Dict]:
        """Get all software/malware used by the threat group"""
        software = []
        
        for obj in self.attack_data.get('objects', []):
            if obj.get('type') == 'relationship':
                if obj.get('source_ref') == group_id and obj.get('relationship_type') == 'uses':
                    target_id = obj.get('target_ref')
                    
                    # Get software (malware or tool)
                    if target_id and (target_id.startswith('malware') or target_id.startswith('tool')):
                        software_obj = self.objects_by_id.get(target_id)
                        if software_obj:
                            software.append({
                                'software': software_obj,
                                'relationship': obj
                            })
        
        return software
    
    def extract_iocs_from_description(self, description: str) -> Dict[str, List[str]]:
        """
        Extract potential IOCs from descriptions
        Note: MITRE descriptions don't usually contain direct IOCs,
        but may reference CVEs, tools, etc.
        """
        import re
        
        iocs = {
            'cves': [],
            'tools': [],
            'domains': [],
            'ips': []
        }
        
        # Extract CVEs
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        iocs['cves'] = list(set(re.findall(cve_pattern, description, re.IGNORECASE)))
        
        # Extract potential domains (very basic)
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        potential_domains = re.findall(domain_pattern, description.lower())
        # Filter out common words that look like domains
        iocs['domains'] = [d for d in potential_domains if '.' in d and len(d) > 5]
        
        return iocs
    
    def create_threat_group_bundle(self, group_name: str) -> Optional[Dict]:
        """Create a complete STIX bundle for a threat group"""
        
        # Find the threat group
        group = self.search_threat_group(group_name)
        
        if not group:
            print(f"[-] Threat group '{group_name}' not found")
            return None
        
        print(f"[+] Found: {group.get('name')}")
        print(f"    ID: {group.get('id')}")
        print(f"    Aliases: {', '.join(group.get('aliases', []))}")
        print(f"    Description: {group.get('description', '')[:150]}...")
        
        group_id = group.get('id')
        
        # Get related data
        techniques = self.get_related_techniques(group_id)
        software = self.get_related_software(group_id)
        
        print(f"\n[+] Found {len(techniques)} techniques")
        print(f"[+] Found {len(software)} software/tools")
        
        # Build STIX bundle
        bundle = {
            "type": "bundle",
            "id": f"bundle--{group_id.split('--')[1]}",
            "spec_version": "2.0",
            "objects": []
        }
        
        # Add the threat actor (intrusion-set)
        bundle['objects'].append(group)
        
        # Add techniques and their relationships
        for item in techniques:
            technique_obj = item['technique']
            relationship_obj = item['relationship']
            
            # Add technique if not already added
            if technique_obj not in bundle['objects']:
                bundle['objects'].append(technique_obj)
            
            # Add relationship
            if relationship_obj not in bundle['objects']:
                bundle['objects'].append(relationship_obj)
        
        # Add software and their relationships
        for item in software:
            software_obj = item['software']
            relationship_obj = item['relationship']
            
            if software_obj not in bundle['objects']:
                bundle['objects'].append(software_obj)
            
            if relationship_obj not in bundle['objects']:
                bundle['objects'].append(relationship_obj)
        
        return bundle
    
    def generate_summary_report(self, group_name: str) -> Dict:
        """Generate a human-readable summary report"""
        
        group = self.search_threat_group(group_name)
        if not group:
            return None
        
        group_id = group.get('id')
        techniques = self.get_related_techniques(group_id)
        software = self.get_related_software(group_id)
        
        # Extract MITRE ATT&CK technique IDs
        technique_ids = []
        technique_details = []
        tactics_map = {}  # Track techniques by tactic
        
        for item in techniques:
            tech = item['technique']
            external_refs = tech.get('external_references', [])
            
            for ref in external_refs:
                if ref.get('source_name') == 'mitre-attack':
                    technique_id = ref.get('external_id', 'Unknown')
                    technique_ids.append(technique_id)
                    
                    tactics = tech.get('kill_chain_phases', [])
                    tactic_names = [t.get('phase_name') for t in tactics]
                    
                    technique_details.append({
                        'id': technique_id,
                        'name': tech.get('name'),
                        'description': tech.get('description', '')[:200] + '...',
                        'tactics': tactics,
                        'tactic_names': tactic_names,
                        'full_object': tech
                    })
                    
                    # Organize by tactic
                    for tactic in tactic_names:
                        if tactic not in tactics_map:
                            tactics_map[tactic] = []
                        tactics_map[tactic].append({
                            'id': technique_id,
                            'name': tech.get('name'),
                            'description': tech.get('description', '')
                        })
                    break
        
        # Software details
        software_details = []
        for item in software:
            soft = item['software']
            software_details.append({
                'name': soft.get('name'),
                'type': soft.get('type'),
                'description': soft.get('description', '')[:200] + '...',
                'full_description': soft.get('description', '')
            })
        
        report = {
            'threat_group': {
                'name': group.get('name'),
                'aliases': group.get('aliases', []),
                'description': group.get('description'),
                'id': group.get('id')
            },
            'techniques': technique_details,
            'technique_count': len(techniques),
            'software': software_details,
            'software_count': len(software),
            'mitre_attack_ids': technique_ids,
            'tactics_map': tactics_map
        }
        
        return report
    
    def generate_hunt_queries(self, report: Dict) -> Dict:
        """Generate detailed hunt queries organized by log type and detection pattern"""
        
        queries = {
            'simple_ioc_searches': [],
            'behavioral_patterns': [],
            'chained_events': [],
            'anomaly_detection': []
        }
        
        techniques = report.get('techniques', [])
        software = report.get('software', [])
        tactics_map = report.get('tactics_map', {})
        group_name = report['threat_group']['name']
        
        # Generate simple IOC searches based on software
        for soft in software[:5]:
            soft_name = soft['name']
            queries['simple_ioc_searches'].append({
                'description': f"Search for {soft_name} indicators",
                'sql_query': f"""
-- Search for {soft_name} in process execution logs
SELECT timestamp, host, process_name, command_line, parent_process, user
FROM process_logs
WHERE process_name LIKE '%{soft_name.lower()}%'
   OR command_line LIKE '%{soft_name.lower()}%'
ORDER BY timestamp DESC;""",
                'log_types': ['Windows Event Logs', 'Sysmon', 'EDR']
            })
        
        # Generate behavioral patterns based on techniques
        technique_patterns = self._generate_technique_patterns(techniques)
        queries['behavioral_patterns'] = technique_patterns
        
        # Generate chained event detections
        chained_detections = self._generate_chained_detections(tactics_map, techniques, software)
        queries['chained_events'] = chained_detections
        
        # Generate anomaly detection queries
        anomaly_queries = self._generate_anomaly_queries(techniques, group_name)
        queries['anomaly_detection'] = anomaly_queries
        
        return queries
    
    def _generate_technique_patterns(self, techniques: List[Dict]) -> List[Dict]:
        """Generate behavioral hunt patterns for specific techniques"""
        patterns = []
        
        # Map common technique IDs to detection patterns
        technique_patterns = {
            'T1566': {  # Phishing
                'description': 'Detect spearphishing email delivery and execution',
                'sql_query': """
-- Spearphishing detection: Email with attachment followed by execution
SELECT 
    e.timestamp AS email_time,
    e.sender, e.recipient, e.subject, e.attachment_name,
    p.timestamp AS exec_time,
    p.process_name, p.command_line, p.parent_process
FROM email_logs e
JOIN process_logs p 
    ON e.recipient_host = p.host 
    AND p.timestamp BETWEEN e.timestamp AND e.timestamp + INTERVAL '5 minutes'
WHERE e.attachment_name LIKE '%.exe' 
   OR e.attachment_name LIKE '%.zip'
   OR e.attachment_name LIKE '%.docm'
   OR e.attachment_name LIKE '%.xlsm'
ORDER BY e.timestamp DESC;""",
                'log_types': ['Email Gateway', 'Windows Event Logs', 'Sysmon']
            },
            'T1059.001': {  # PowerShell
                'description': 'Detect suspicious PowerShell execution',
                'sql_query': """
-- Suspicious PowerShell patterns
SELECT timestamp, host, user, command_line, parent_process, process_id
FROM process_logs
WHERE process_name IN ('powershell.exe', 'pwsh.exe')
  AND (
    command_line LIKE '%EncodedCommand%'
    OR command_line LIKE '%-enc%'
    OR command_line LIKE '%DownloadString%'
    OR command_line LIKE '%IEX%'
    OR command_line LIKE '%Invoke-Expression%'
    OR command_line LIKE '%-WindowStyle Hidden%'
    OR command_line LIKE '%bypass%'
  )
ORDER BY timestamp DESC;""",
                'log_types': ['Windows Event Logs (4688)', 'Sysmon (Event 1)', 'PowerShell Logs (4104)']
            },
            'T1071': {  # Application Layer Protocol (C2)
                'description': 'Detect C2 communication over common protocols',
                'sql_query': """
-- Detect potential C2 beaconing behavior
SELECT 
    src_ip, dst_ip, dst_port, protocol,
    COUNT(*) as connection_count,
    AVG(bytes_sent) as avg_bytes,
    STDDEV(EXTRACT(EPOCH FROM (timestamp - LAG(timestamp) OVER (PARTITION BY src_ip, dst_ip ORDER BY timestamp)))) as beacon_jitter
FROM network_logs
WHERE dst_port IN (80, 443, 8080, 8443)
GROUP BY src_ip, dst_ip, dst_port, protocol
HAVING COUNT(*) > 50  -- Regular beaconing
   AND STDDEV(EXTRACT(EPOCH FROM (timestamp - LAG(timestamp) OVER (PARTITION BY src_ip, dst_ip ORDER BY timestamp)))) < 10  -- Consistent timing
ORDER BY connection_count DESC;""",
                'log_types': ['Firewall', 'Proxy', 'NetFlow', 'Zeek/Bro']
            },
            'T1055': {  # Process Injection
                'description': 'Detect process injection techniques',
                'sql_query': """
-- Process injection indicators (Sysmon Event 8, 10)
SELECT 
    timestamp, host, 
    source_process, source_process_id,
    target_process, target_process_id,
    granted_access, call_trace
FROM sysmon_logs
WHERE event_id IN (8, 10)  -- CreateRemoteThread, ProcessAccess
  AND (
    granted_access LIKE '%0x1F%'  -- PROCESS_ALL_ACCESS
    OR call_trace LIKE '%UNKNOWN%'
  )
ORDER BY timestamp DESC;""",
                'log_types': ['Sysmon']
            },
            'T1003': {  # Credential Dumping
                'description': 'Detect credential access attempts',
                'sql_query': """
-- LSASS access and credential dumping
SELECT timestamp, host, process_name, command_line, user, target_process
FROM process_logs
WHERE (
    -- LSASS access
    target_process = 'lsass.exe'
    -- Credential dumping tools
    OR command_line LIKE '%procdump%lsass%'
    OR command_line LIKE '%mimikatz%'
    OR command_line LIKE '%sekurlsa%'
    OR process_name IN ('procdump.exe', 'procdump64.exe')
    -- Registry credential access
    OR command_line LIKE '%reg save%HKLM\\SAM%'
    OR command_line LIKE '%reg save%HKLM\\SECURITY%'
)
ORDER BY timestamp DESC;""",
                'log_types': ['Windows Event Logs', 'Sysmon', 'EDR']
            },
            'T1053': {  # Scheduled Task/Job
                'description': 'Detect persistence via scheduled tasks',
                'sql_query': """
-- Scheduled task creation for persistence
SELECT timestamp, host, user, task_name, task_command, trigger_type
FROM scheduled_task_logs
WHERE event_type = 'TaskCreated'
  AND (
    task_command LIKE '%powershell%'
    OR task_command LIKE '%cmd.exe%'
    OR task_command LIKE '%wscript%'
    OR task_command LIKE '%cscript%'
  )
ORDER BY timestamp DESC;""",
                'log_types': ['Windows Event Logs (4698)']
            }
        }
        
        # Match techniques to patterns
        for tech in techniques[:10]:  # Limit to first 10 techniques
            tech_id = tech['id'].split('.')[0]  # Get base technique ID
            
            if tech_id in technique_patterns:
                pattern = technique_patterns[tech_id].copy()
                pattern['technique_id'] = tech['id']
                pattern['technique_name'] = tech['name']
                patterns.append(pattern)
        
        return patterns
    
    def _generate_chained_detections(self, tactics_map: Dict, techniques: List[Dict], software: List[Dict]) -> List[Dict]:
        """Generate detection logic for chained/sequential events"""
        chains = []
        
        # Chain 1: Initial Access → Execution → Persistence
        if 'initial-access' in tactics_map and 'execution' in tactics_map:
            chains.append({
                'chain_name': 'Initial Compromise to Persistence',
                'description': 'Detect initial access followed by execution and persistence establishment',
                'stages': ['initial-access', 'execution', 'persistence'],
                'sql_query': """
-- Multi-stage detection: Email → Execution → Persistence
WITH email_events AS (
    SELECT timestamp as email_time, recipient_host, attachment_name
    FROM email_logs
    WHERE attachment_name LIKE '%.exe' OR attachment_name LIKE '%.zip'
),
execution_events AS (
    SELECT timestamp as exec_time, host, process_name, command_line, parent_process
    FROM process_logs
    WHERE parent_process IN ('outlook.exe', 'winword.exe', 'excel.exe')
),
persistence_events AS (
    SELECT timestamp as persist_time, host, registry_key, registry_value
    FROM registry_logs
    WHERE registry_key LIKE '%\\Run%' 
       OR registry_key LIKE '%\\RunOnce%'
)
SELECT 
    e.email_time, e.recipient_host, e.attachment_name,
    ex.exec_time, ex.process_name, ex.command_line,
    p.persist_time, p.registry_key, p.registry_value
FROM email_events e
JOIN execution_events ex 
    ON e.recipient_host = ex.host 
    AND ex.exec_time BETWEEN e.email_time AND e.email_time + INTERVAL '10 minutes'
JOIN persistence_events p 
    ON ex.host = p.host 
    AND p.persist_time BETWEEN ex.exec_time AND ex.exec_time + INTERVAL '5 minutes'
ORDER BY e.email_time DESC;""",
                'log_types': ['Email Gateway', 'Windows Event Logs', 'Sysmon', 'EDR'],
                'time_window': '10-15 minutes',
                'techniques': [t['id'] for t in techniques if any(tactic in ['initial-access', 'execution', 'persistence'] for tactic in t.get('tactic_names', []))]
            })
        
        # Chain 2: Execution → Discovery → Lateral Movement
        if 'execution' in tactics_map and 'discovery' in tactics_map:
            chains.append({
                'chain_name': 'Discovery and Lateral Movement',
                'description': 'Detect reconnaissance followed by lateral movement attempts',
                'stages': ['execution', 'discovery', 'lateral-movement'],
                'sql_query': """
-- Detect discovery commands followed by lateral movement
WITH discovery_commands AS (
    SELECT timestamp as disc_time, host, user, command_line
    FROM process_logs
    WHERE command_line LIKE '%net view%'
       OR command_line LIKE '%net user%'
       OR command_line LIKE '%net group%'
       OR command_line LIKE '%nltest%'
       OR command_line LIKE '%dsquery%'
       OR command_line LIKE '%ipconfig%'
       OR command_line LIKE '%whoami%'
),
lateral_movement AS (
    SELECT timestamp as lat_time, src_host, dst_host, user, service_name
    FROM authentication_logs
    WHERE event_type = 'RemoteLogon'
       OR service_name IN ('psexec', 'wmi', 'winrm')
)
SELECT 
    d.disc_time, d.host as source_host, d.user, d.command_line,
    l.lat_time, l.dst_host as target_host, l.service_name
FROM discovery_commands d
JOIN lateral_movement l 
    ON d.host = l.src_host 
    AND d.user = l.user
    AND l.lat_time BETWEEN d.disc_time AND d.disc_time + INTERVAL '30 minutes'
ORDER BY d.disc_time DESC;""",
                'log_types': ['Windows Event Logs', 'Sysmon', 'Network Logs'],
                'time_window': '30 minutes',
                'techniques': [t['id'] for t in techniques if any(tactic in ['discovery', 'lateral-movement'] for tactic in t.get('tactic_names', []))]
            })
        
        # Chain 3: Credential Access → Lateral Movement → Exfiltration
        if 'credential-access' in tactics_map and 'exfiltration' in tactics_map:
            chains.append({
                'chain_name': 'Credential Theft to Data Exfiltration',
                'description': 'Detect credential dumping followed by data staging and exfiltration',
                'stages': ['credential-access', 'collection', 'exfiltration'],
                'sql_query': """
-- Credential access → Data staging → Exfiltration
WITH credential_access AS (
    SELECT timestamp as cred_time, host, user, process_name, command_line
    FROM process_logs
    WHERE target_process = 'lsass.exe'
       OR command_line LIKE '%mimikatz%'
       OR command_line LIKE '%procdump%lsass%'
),
data_staging AS (
    SELECT timestamp as stage_time, host, user, file_path, file_size
    FROM file_logs
    WHERE (file_path LIKE '%.zip' OR file_path LIKE '%.rar' OR file_path LIKE '%.7z')
      AND file_size > 10000000  -- Files > 10MB
),
exfil_activity AS (
    SELECT timestamp as exfil_time, src_ip, dst_ip, bytes_sent, protocol
    FROM network_logs
    WHERE bytes_sent > 50000000  -- Large outbound transfer
      AND dst_ip NOT IN (SELECT ip FROM known_good_destinations)
)
SELECT 
    ca.cred_time, ca.host, ca.user, ca.process_name,
    ds.stage_time, ds.file_path, ds.file_size,
    ea.exfil_time, ea.dst_ip, ea.bytes_sent
FROM credential_access ca
JOIN data_staging ds 
    ON ca.host = ds.host 
    AND ds.stage_time BETWEEN ca.cred_time AND ca.cred_time + INTERVAL '2 hours'
JOIN exfil_activity ea 
    ON ds.host = ea.src_ip 
    AND ea.exfil_time BETWEEN ds.stage_time AND ds.stage_time + INTERVAL '1 hour'
ORDER BY ca.cred_time DESC;""",
                'log_types': ['Windows Event Logs', 'Sysmon', 'Network Logs', 'Firewall', 'Proxy'],
                'time_window': '2-3 hours',
                'techniques': [t['id'] for t in techniques if any(tactic in ['credential-access', 'collection', 'exfiltration'] for tactic in t.get('tactic_names', []))]
            })
        
        # Chain 4: PowerShell execution → Network connection (common C2 pattern)
        chains.append({
            'chain_name': 'PowerShell C2 Callback',
            'description': 'Detect PowerShell execution immediately followed by network connection',
            'stages': ['execution', 'command-and-control'],
            'sql_query': """
-- PowerShell execution with immediate network callback
WITH powershell_exec AS (
    SELECT timestamp as ps_time, host, process_id, command_line, user
    FROM process_logs
    WHERE process_name IN ('powershell.exe', 'pwsh.exe')
      AND (command_line LIKE '%DownloadString%'
           OR command_line LIKE '%WebClient%'
           OR command_line LIKE '%Net.Sockets%'
           OR command_line LIKE '%-enc%')
),
network_connections AS (
    SELECT timestamp as conn_time, src_ip, dst_ip, dst_port, process_id
    FROM network_logs
    WHERE dst_port IN (80, 443, 8080, 8443)
)
SELECT 
    ps.ps_time, ps.host, ps.user, ps.command_line,
    nc.conn_time, nc.dst_ip, nc.dst_port,
    EXTRACT(EPOCH FROM (nc.conn_time - ps.ps_time)) as seconds_between
FROM powershell_exec ps
JOIN network_connections nc 
    ON ps.host = nc.src_ip 
    AND ps.process_id = nc.process_id
    AND nc.conn_time BETWEEN ps.ps_time AND ps.ps_time + INTERVAL '2 minutes'
ORDER BY ps.ps_time DESC;""",
            'log_types': ['Windows Event Logs', 'Sysmon', 'Network Logs', 'Firewall'],
            'time_window': '2 minutes',
            'techniques': ['T1059.001', 'T1071']
        })
        
        return chains
    
    def _generate_anomaly_queries(self, techniques: List[Dict], group_name: str) -> List[Dict]:
        """Generate anomaly detection queries"""
        anomalies = []
        
        anomalies.append({
            'anomaly_type': 'Rare Process-Parent Relationship',
            'description': 'Detect unusual parent-child process relationships indicative of compromise',
            'sql_query': f"""
-- Detect anomalous process relationships
WITH normal_relationships AS (
    SELECT parent_process, process_name, COUNT(*) as frequency
    FROM process_logs
    WHERE timestamp > CURRENT_DATE - INTERVAL '30 days'
    GROUP BY parent_process, process_name
    HAVING COUNT(*) > 10  -- Seen more than 10 times = "normal"
)
SELECT p.timestamp, p.host, p.user, p.parent_process, p.process_name, p.command_line
FROM process_logs p
LEFT JOIN normal_relationships nr 
    ON p.parent_process = nr.parent_process 
    AND p.process_name = nr.process_name
WHERE nr.frequency IS NULL  -- Not in our "normal" set
  AND p.parent_process NOT IN ('explorer.exe', 'services.exe', 'svchost.exe')
ORDER BY p.timestamp DESC;""",
            'log_types': ['Windows Event Logs', 'Sysmon'],
            'baseline_required': True
        })
        
        anomalies.append({
            'anomaly_type': 'Unusual Outbound Connections',
            'description': 'Detect hosts making connections to rare/new external IPs',
            'sql_query': """
-- Identify connections to previously unseen destinations
WITH historical_destinations AS (
    SELECT DISTINCT dst_ip
    FROM network_logs
    WHERE timestamp BETWEEN CURRENT_DATE - INTERVAL '30 days' AND CURRENT_DATE - INTERVAL '1 day'
),
recent_connections AS (
    SELECT timestamp, src_ip, dst_ip, dst_port, bytes_sent
    FROM network_logs
    WHERE timestamp > CURRENT_DATE - INTERVAL '1 day'
      AND dst_ip NOT IN (SELECT ip FROM internal_ip_ranges)
)
SELECT rc.*
FROM recent_connections rc
LEFT JOIN historical_destinations hd ON rc.dst_ip = hd.dst_ip
WHERE hd.dst_ip IS NULL  -- Never seen before
ORDER BY rc.timestamp DESC;""",
            'log_types': ['Firewall', 'Network Logs', 'Proxy'],
            'baseline_required': True
        })
        
        anomalies.append({
            'anomaly_type': 'Off-Hours Activity',
            'description': f'Detect {group_name} techniques occurring during off-hours',
            'sql_query': """
-- Activity during unusual hours (customize for your organization)
SELECT timestamp, host, user, process_name, command_line
FROM process_logs
WHERE (
    -- Off-hours: Before 6 AM or after 8 PM, or weekends
    EXTRACT(HOUR FROM timestamp) < 6 
    OR EXTRACT(HOUR FROM timestamp) > 20
    OR EXTRACT(DOW FROM timestamp) IN (0, 6)  -- Sunday, Saturday
)
AND (
    process_name IN ('powershell.exe', 'cmd.exe', 'wscript.exe')
    OR command_line LIKE '%net user%'
    OR command_line LIKE '%net group%'
    OR command_line LIKE '%psexec%'
)
ORDER BY timestamp DESC;""",
            'log_types': ['Windows Event Logs', 'Sysmon'],
            'baseline_required': False
        })
        
        return anomalies


def main():
    """Main execution"""

    # Set up argument parser
    parser = argparse.ArgumentParser(
        description='MITRE ATT&CK Threat Group STIX Extractor - Fetches STIX 2.0 data for specific threat actors',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s APT29                    # Extract data for APT29
  %(prog)s "Lazarus Group"          # Extract data for Lazarus Group (use quotes for multi-word names)
  %(prog)s list                     # List all available threat groups
  %(prog)s                          # Interactive mode - prompts for threat group name

Output Files:
  The tool generates three files per threat group:
    - mitre_<group>_stix_<timestamp>.json        : STIX 2.0 bundle
    - mitre_<group>_report_<timestamp>.json      : Detailed analysis report
    - mitre_<group>_hunt_queries_<timestamp>.json: SQL-based threat hunting queries

For more information: https://attack.mitre.org/
        ''')

    parser.add_argument(
        'threat_group',
        nargs='*',
        help='Name or alias of the threat group (e.g., APT29, "Lazarus Group"). Use "list" to show all available groups.'
    )

    parser.add_argument(
        '-v', '--version',
        action='version',
        version='%(prog)s 1.0'
    )

    args = parser.parse_args()

    print("="*70)
    print("MITRE ATT&CK Threat Group STIX Extractor")
    print("="*70)

    # Get threat group name from command line or prompt
    if args.threat_group:
        threat_group_name = ' '.join(args.threat_group)
    else:
        threat_group_name = input("\nEnter threat group name (e.g., APT29, Lazarus Group): ").strip()

    if not threat_group_name:
        print("[-] No threat group specified. Exiting.")
        parser.print_help()
        return None
    
    # Initialize extractor
    extractor = MITREThreatGroupExtractor()
    
    # Fetch MITRE data
    if not extractor.fetch_attack_data():
        print("[-] Failed to fetch MITRE ATT&CK data. Exiting.")
        return None
    
    # Check if user wants to list all groups
    if threat_group_name.lower() in ['list', 'all', 'show']:
        print("\n[*] Available Threat Groups:")
        groups = extractor.list_all_threat_groups()
        for i, group in enumerate(groups, 1):
            print(f"\n{i}. {group['name']}")
            if group['aliases']:
                print(f"   Aliases: {', '.join(group['aliases'])}")
        print(f"\nTotal: {len(groups)} threat groups")
        return None
    
    # Extract threat group data
    bundle = extractor.create_threat_group_bundle(threat_group_name)
    
    if not bundle:
        print("\n[!] Threat group not found. Try running with 'list' to see all available groups:")
        print(f"    python quickCTI.py list")
        return None
    
    # Generate summary report
    report = extractor.generate_summary_report(threat_group_name)
    
    # Save STIX bundle
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    group_name_clean = threat_group_name.replace(' ', '_').replace('/', '_')
    
    stix_filename = f"mitre_{group_name_clean}_stix_{timestamp}.json"
    with open(stix_filename, 'w') as f:
        json.dump(bundle, f, indent=2)
    print(f"\n[+] STIX bundle saved: {stix_filename}")
    
    # Save summary report
    report_filename = f"mitre_{group_name_clean}_report_{timestamp}.json"
    with open(report_filename, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"[+] Summary report saved: {report_filename}")
    
    # Print summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"\nThreat Group: {report['threat_group']['name']}")
    print(f"Aliases: {', '.join(report['threat_group']['aliases'])}")
    print(f"\nTechniques: {report['technique_count']}")
    print(f"Software/Tools: {report['software_count']}")
    
    print("\n[*] Top 10 MITRE ATT&CK Techniques:")
    for i, tech in enumerate(report['techniques'][:10], 1):
        tactics = ', '.join([phase.get('phase_name', '') for phase in tech.get('tactics', [])])
        print(f"  {i}. {tech['id']} - {tech['name']}")
        print(f"     Tactics: {tactics}")
    
    if report['software']:
        print("\n[*] Associated Software/Malware:")
        for i, soft in enumerate(report['software'][:10], 1):
            print(f"  {i}. {soft['name']} ({soft['type']})")
    
    print("\n[+] Data ready for retrospective hunt operations!")
    print(f"[+] STIX objects in bundle: {len(bundle['objects'])}")
    
    # Generate comprehensive hunt queries
    print("\n" + "="*70)
    print("SUGGESTED HUNT QUERIES")
    print("="*70)
    
    hunt_queries = extractor.generate_hunt_queries(report)
    
    # Display simple IOC searches
    if hunt_queries['simple_ioc_searches']:
        print("\n### 1. SIMPLE IOC SEARCHES")
        print("# Quick wins - search for known malware/tools used by this threat group")
        print("-" * 70)
        for i, query in enumerate(hunt_queries['simple_ioc_searches'][:3], 1):
            print(f"\n## Query {i}: {query['description']}")
            print(f"## Log Types: {', '.join(query['log_types'])}")
            print(query['sql_query'])
    
    # Display behavioral patterns
    if hunt_queries['behavioral_patterns']:
        print("\n\n### 2. BEHAVIORAL PATTERN DETECTIONS")
        print("# Detect specific TTPs used by this threat group")
        print("-" * 70)
        for i, pattern in enumerate(hunt_queries['behavioral_patterns'][:5], 1):
            print(f"\n## Pattern {i}: {pattern['technique_name']} ({pattern['technique_id']})")
            print(f"## Description: {pattern['description']}")
            print(f"## Log Types: {', '.join(pattern['log_types'])}")
            print(pattern['sql_query'])
    
    # Display chained event detections
    if hunt_queries['chained_events']:
        print("\n\n### 3. CHAINED EVENT DETECTIONS (MULTI-STAGE ATTACKS)")
        print("# Correlate multiple events to detect attack chains")
        print("# These are higher-fidelity detections with fewer false positives")
        print("-" * 70)
        for i, chain in enumerate(hunt_queries['chained_events'], 1):
            print(f"\n## Chain {i}: {chain['chain_name']}")
            print(f"## Description: {chain['description']}")
            print(f"## Attack Stages: {' → '.join(chain['stages'])}")
            print(f"## Time Window: {chain.get('time_window', 'N/A')}")
            print(f"## Log Types: {', '.join(chain['log_types'])}")
            if 'techniques' in chain and chain['techniques']:
                print(f"## Related Techniques: {', '.join(chain['techniques'][:5])}")
            print(chain['sql_query'])
    
    # Display anomaly detection queries
    if hunt_queries['anomaly_detection']:
        print("\n\n### 4. ANOMALY-BASED DETECTIONS")
        print("# Baseline-based detections for unusual activity")
        print("# Requires historical data for comparison")
        print("-" * 70)
        for i, anomaly in enumerate(hunt_queries['anomaly_detection'], 1):
            print(f"\n## Anomaly {i}: {anomaly['anomaly_type']}")
            print(f"## Description: {anomaly['description']}")
            print(f"## Baseline Required: {anomaly.get('baseline_required', 'Unknown')}")
            print(f"## Log Types: {', '.join(anomaly['log_types'])}")
            print(anomaly['sql_query'])
    
    # Save hunt queries to file
    queries_filename = f"mitre_{group_name_clean}_hunt_queries_{timestamp}.json"
    with open(queries_filename, 'w') as f:
        json.dump(hunt_queries, f, indent=2)
    print(f"\n\n[+] Hunt queries saved: {queries_filename}")
    
    # Summary of hunt strategy
    print("\n" + "="*70)
    print("HUNT STRATEGY RECOMMENDATIONS")
    print("="*70)
    print(f"""
For {report['threat_group']['name']}, implement a layered detection approach:

1. IMMEDIATE ACTIONS (Day 1):
   - Run simple IOC searches across all historical missions
   - Focus on known malware: {', '.join([s['name'] for s in report['software'][:3]])}
   - Search for top techniques: {', '.join(report['mitre_attack_ids'][:5])}

2. BEHAVIORAL HUNTING (Days 2-3):
   - Deploy behavioral pattern detections
   - Look for technique-specific indicators
   - Focus on high-confidence patterns with low false positives

3. CORRELATION HUNTING (Week 1):
   - Implement chained event detections
   - Correlate across multiple log sources
   - Identify multi-stage attack patterns
   - Time windows: {', '.join(set([c.get('time_window', 'varies') for c in hunt_queries['chained_events']]))}

4. CONTINUOUS MONITORING (Ongoing):
   - Establish baselines for anomaly detection
   - Monitor for unusual parent-child process relationships
   - Track connections to rare/new destinations
   - Alert on off-hours activity matching threat group TTPs

5. THREAT INTELLIGENCE UPDATES:
   - Re-run hunts when new {report['threat_group']['name']} intel is published
   - Update detection logic based on new techniques
   - Refine queries based on false positive analysis

PRIORITIZE THESE LOG SOURCES:
   - Windows Event Logs (Security, System, Application)
   - Sysmon (Events 1, 3, 7, 8, 10, 11)
   - PowerShell Logs (Event 4104)
   - Network Logs (Firewall, Proxy, NetFlow, Zeek)
   - Email Gateway Logs
   - EDR/XDR telemetry
""")
    
    return bundle, report, hunt_queries


if __name__ == "__main__":
    try:
        result = main()
        if result:
            bundle, report, hunt_queries = result
    except KeyboardInterrupt:
        print("\n\n[-] Interrupted by user")
        sys.exit(1)
