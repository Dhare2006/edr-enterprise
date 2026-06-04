"""
EDR Process Monitoring Engine
"""
import psutil
import time
import threading
import json
from datetime import datetime
from plyer import notification

# Threat signatures
MALICIOUS_PROCESSES = {
    'ransomware.exe', 'wannacry.exe', 'locky.exe', 'cryptolocker.exe',
    'xmrig.exe', 'miner.exe', 'cgminer.exe', 'minerd.exe',
    'nc.exe', 'netcat.exe', 'reverse_shell.exe', 'nc64.exe',
    'mimikatz.exe', 'procdump.exe', 'psexec.exe', 'powershell.exe'
}

SUSPICIOUS_PATTERNS = [
    'powershell -enc', 'powershell -e', 'cmd /c', 'schtasks /create',
    'reg add', 'sc create', 'net user', 'net localgroup',
    'vssadmin delete', 'wbadmin delete', 'cscript', 'wscript',
    '-EncodedCommand', '-exec bypass', 'bypass -noprofile'
]

# Store detected threats
detected_threats = []
monitoring_active = True

def analyze_process(proc):
    """Analyze a single process for malicious behavior"""
    try:
        name = proc.name().lower()
        pid = proc.pid
        
        # Get CPU and memory usage
        cpu = proc.cpu_percent(interval=0.1)
        memory = proc.memory_percent()
        
        # Get command line
        try:
            cmdline = ' '.join(proc.cmdline())
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
        
        # Detection rules
        severity = None
        reason = None
        
        # Rule 1: Known malware
        if name in MALICIOUS_PROCESSES:
            severity = 'CRITICAL'
            reason = f'Known malware process: {name}'
        
       # Rule 2: High CPU (possible crypto miner) - Skip System Idle Process
elif cpu > 80 and name != 'system idle process' and name != 'System Idle Process':
    severity = 'HIGH'
    reason = f'Anomalous CPU usage: {cpu}%'
        
        # Rule 3: Suspicious command line
        elif cmdline and any(p in cmdline.lower() for p in SUSPICIOUS_PATTERNS):
            severity = 'HIGH'
            reason = f'Suspicious command: {cmdline[:100]}'
        
        # Rule 4: Suspicious network port
        elif any(port in str(conn) for port in ['4444', '1337', '31337', '6667'] for conn in connections):
            severity = 'CRITICAL'
            reason = f'Suspicious network connection: {connections}'
        
        # Rule 5: High memory usage
        elif memory > 50:
            severity = 'MEDIUM'
            reason = f'High memory usage: {memory}%'
        
        if severity:
            threat = {
                'process_name': name,
                'process_pid': pid,
                'severity': severity,
                'reason': reason,
                'cmdline': cmdline[:200],
                'connections': str(connections),
                'cpu_usage': round(cpu, 1),
                'memory_usage': round(memory, 1),
                'action_taken': 'terminated',
                'timestamp': datetime.now().isoformat()
            }
            
            # Terminate malicious process
            try:
                proc.terminate()
                time.sleep(1)
                if proc.is_running():
                    proc.kill()
                threat['action_taken'] = 'terminated'
            except:
                threat['action_taken'] = 'failed to terminate'
            
            # Send desktop notification
            try:
                notification.notify(
                    title='🚨 EDR Alert',
                    message=f'{severity}: {reason[:100]}',
                    timeout=5
                )
            except:
                pass
            
            return threat
    
    except Exception as e:
        pass
    
    return None

def start_monitoring():
    """Start the EDR monitoring thread"""
    global monitoring_active, detected_threats
    
    print("🟢 EDR Monitoring Engine Started")
    print("Monitoring for: Malware, Miners, Reverse Shells\n")
    
    while monitoring_active:
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                threat = analyze_process(proc)
                if threat:
                    detected_threats.insert(0, threat)
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚨 {threat['severity']} - {threat['reason'][:50]}")
            
            time.sleep(3)
        except Exception as e:
            print(f"Monitor error: {e}")
            time.sleep(10)

def get_threats():
    """Get list of detected threats"""
    return detected_threats[:100]

def clear_threats():
    """Clear all detected threats"""
    global detected_threats
    detected_threats = []

def stop_monitoring():
    """Stop the monitoring thread"""
    global monitoring_active
    monitoring_active = False