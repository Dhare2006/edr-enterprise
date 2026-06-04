"""
EDR Process Monitoring Engine - 50+ Threat Patterns
"""
import psutil
import time
import threading
from datetime import datetime
from plyer import notification

# ==================== 50+ MALICIOUS PROCESS PATTERNS ====================
MALICIOUS_PROCESSES = {
    # Ransomware (15 patterns)
    'ransomware.exe', 'wannacry.exe', 'locky.exe', 'cryptolocker.exe',
    'cerber.exe', 'zepto.exe', 'cryptowall.exe', 'teslacrypt.exe',
    'jigsaw.exe', 'badrabbit.exe', 'petya.exe', 'notpetya.exe',
    'gandcrab.exe', 'ryuk.exe', 'revil.exe',
    
    # Crypto Miners (15 patterns)
    'xmrig.exe', 'miner.exe', 'cgminer.exe', 'minerd.exe',
    'ethminer.exe', 'nbminer.exe', 'teamredminer.exe', 'lolminer.exe',
    't-rex.exe', 'gminer.exe', 'phoenixminer.exe', 'claymore.exe',
    'srbm Miner.exe', 'nanominer.exe', 'wildrig.exe',
    
    # Reverse Shells (10 patterns)
    'nc.exe', 'netcat.exe', 'reverse_shell.exe', 'nc64.exe',
    'socat.exe', 'ncat.exe', 'powercat.ps1', 'evil-winrm.exe',
    'pypykatz.exe', 'mimikatz.exe',
    
    # Hack Tools (10 patterns)
    'procdump.exe', 'psexec.exe', 'wce.exe', 'fgdump.exe',
    'hashdump.exe', 'cain.exe', 'abel.exe', 'hydra.exe',
    'john.exe', 'hashcat.exe',
    
    # Suspicious Executables (10 patterns)
    'payload.exe', 'backdoor.exe', 'trojan.exe', 'virus.exe',
    'malware.exe', 'spyware.exe', 'keylogger.exe', 'rat.exe',
    'bot.exe', 'worm.exe'
}

# ==================== 20+ SUSPICIOUS COMMAND PATTERNS ====================
SUSPICIOUS_COMMANDS = [
    # PowerShell attacks
    'powershell -enc', 'powershell -e', 'powershell -windowstyle hidden',
    'powershell -exec bypass', 'IEX(New-Object Net.WebClient).DownloadString',
    'Invoke-Expression', 'Invoke-Mimikatz', 'Invoke-PowerShellTcp',
    
    # CMD attacks
    'cmd /c', 'cmd.exe /c', 'start /b',
    
    # Persistence
    'schtasks /create', 'reg add HKLM', 'sc create',
    'wmic process call create', 'msiexec /quiet',
    
    # Credential theft
    'net user', 'net localgroup', 'whoami /priv', 'sekurlsa::logonpasswords',
    
    # Ransomware commands
    'vssadmin delete shadows', 'wbadmin delete catalog', 'bcdedit /set',
    
    # Download and execute
    'certutil -urlcache', 'bitsadmin /transfer', 'curl -o', 'wget -O',
    'Invoke-WebRequest', 'Net.WebClient'
]

# ==================== SUSPICIOUS NETWORK PORTS ====================
SUSPICIOUS_PORTS = ['4444', '1337', '31337', '6667', '5555', '8080', '8443', '9999']

# Store detected threats
detected_threats = []
monitoring_active = True
total_scans = 0

def analyze_process(proc):
    """Analyze process with 50+ detection rules"""
    try:
        name = proc.name().lower()
        pid = proc.pid
        
        # Skip system processes (reduce false positives)
        skip_processes = ['system idle process', 'System Idle Process', 'svchost.exe', 
                         'services.exe', 'lsass.exe', 'winlogon.exe', 'csrss.exe',
                         'smss.exe', 'wininit.exe', 'spoolsv.exe']
        if name in skip_processes:
            return None
        
        # Get metrics
        cpu = proc.cpu_percent(interval=0.1)
        memory = proc.memory_percent()
        
        # Get command line
        try:
            cmdline = ' '.join(proc.cmdline()).lower()
        except:
            cmdline = ''
        
        # Get network connections
        connections = []
        try:
            for conn in proc.connections():
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    connections.append(f"{conn.raddr.ip}:{conn.raddr.port}")
        except:
            pass
        
        severity = None
        reason = None
        detection_type = None
        
        # RULE 1: Known malware (CRITICAL)
        if name in MALICIOUS_PROCESSES:
            severity = 'CRITICAL'
            detection_type = 'Malware'
            reason = f'Known malware: {name}'
        
        # RULE 2: Crypto miner (HIGH) - 200%+ CPU for miners
        elif cpu > 200:
            severity = 'HIGH'
            detection_type = 'Crypto Miner'
            reason = f'Anomalous CPU: {cpu}% (mining pattern)'
        
        # RULE 3: Suspicious command (HIGH)
        elif any(cmd in cmdline for cmd in SUSPICIOUS_COMMANDS):
            severity = 'HIGH'
            detection_type = 'Suspicious Command'
            reason = f'Detected: {cmdline[:80]}'
        
        # RULE 4: Reverse shell port (CRITICAL)
        elif any(port in str(conn) for port in SUSPICIOUS_PORTS for conn in connections):
            severity = 'CRITICAL'
            detection_type = 'Reverse Shell'
            reason = f'C2 connection on port {connections}'
        
        # RULE 5: High memory (MEDIUM)
        elif memory > 60:
            severity = 'MEDIUM'
            detection_type = 'Memory Bomb'
            reason = f'Memory usage: {memory}%'
        
        # RULE 6: Unsigned PowerShell (MEDIUM)
        elif name == 'powershell.exe' and len(cmdline) > 100:
            severity = 'MEDIUM'
            detection_type = 'Suspicious PowerShell'
            reason = f'Long PowerShell command detected'
        
        if severity:
            threat = {
                'process_name': name,
                'process_pid': pid,
                'severity': severity,
                'detection_type': detection_type,
                'reason': reason,
                'cpu_usage': round(cpu, 1),
                'memory_usage': round(memory, 1),
                'action_taken': 'terminated',
                'timestamp': datetime.now().isoformat()
            }
            
            # Terminate process
            try:
                proc.terminate()
                time.sleep(1)
                if proc.is_running():
                    proc.kill()
            except:
                threat['action_taken'] = 'failed'
            
            # Desktop notification
            try:
                notification.notify(
                    title=f'🚨 {severity} - {detection_type}',
                    message=reason[:100],
                    timeout=5
                )
            except:
                pass
            
            return threat
    except:
        pass
    return None

def start_monitoring():
    """Start EDR monitoring"""
    global monitoring_active, detected_threats, total_scans
    
    print("🟢 EDR Monitoring Engine Started")
    print(f"📋 Loaded {len(MALICIOUS_PROCESSES)} malware patterns")
    print(f"📋 Loaded {len(SUSPICIOUS_COMMANDS)} command patterns")
    print(f"📋 Loaded {len(SUSPICIOUS_PORTS)} suspicious ports")
    print("\nMonitoring for: Malware, Miners, Reverse Shells, Ransomware\n")
    
    while monitoring_active:
        try:
            total_scans += 1
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                threat = analyze_process(proc)
                if threat:
                    detected_threats.insert(0, threat)
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚨 {threat['severity']} - {threat['detection_type']} - {threat['reason'][:60]}")
            
            time.sleep(3)
        except Exception as e:
            print(f"Monitor error: {e}")
            time.sleep(10)

def get_threats():
    return detected_threats[:100]

def clear_threats():
    global detected_threats
    detected_threats = []

def get_stats():
    total = len(detected_threats)
    critical = len([t for t in detected_threats if t['severity'] == 'CRITICAL'])
    high = len([t for t in detected_threats if t['severity'] == 'HIGH'])
    medium = len([t for t in detected_threats if t['severity'] == 'MEDIUM'])
    return total, critical, high, medium