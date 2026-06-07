import os
import json
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from dotenv import load_dotenv
from database import query, query_one

load_dotenv()

DOWNLOADS_DIR = os.getenv('DOWNLOADS_DIR', '/opt/honeypot/cowrie-data/downloads/')
TTY_DIR = os.getenv('TTY_DIR', '/opt/honeypot/cowrie-data/tty/')


def get_attackers():
    rows = query("""
        SELECT 
            a.ip, a.country, a.isp, a.lat, a.lon, a.first_seen, a.last_seen,
            COUNT(e.id) as attacks
        FROM attackers a
        LEFT JOIN events e ON e.src_ip = a.ip
        WHERE e.event_type = 'cowrie.session.connect'
        GROUP BY a.ip
        ORDER BY attacks DESC
    """)
    return {r['ip']: r for r in rows}


def get_ip_counts():
    rows = query("""
        SELECT src_ip, COUNT(*) as count
        FROM events
        WHERE event_type = 'cowrie.session.connect'
        GROUP BY src_ip
    """)
    return {r['src_ip']: r['count'] for r in rows}


def get_top_passwords(limit=20):
    rows = query("""
        SELECT password, COUNT(*) as count
        FROM login_attempts
        WHERE password IS NOT NULL
        GROUP BY password
        ORDER BY count DESC
        LIMIT ?
    """, (limit,))
    return [(r['password'], r['count']) for r in rows]


def get_top_usernames(limit=20):
    rows = query("""
        SELECT username, COUNT(*) as count
        FROM login_attempts
        WHERE username IS NOT NULL
        GROUP BY username
        ORDER BY count DESC
        LIMIT ?
    """, (limit,))
    return [(r['username'], r['count']) for r in rows]


def get_summary():
    return query_one("""
        SELECT
            (SELECT COUNT(*) FROM events WHERE event_type='cowrie.session.connect') as total_attacks,
            (SELECT COUNT(*) FROM attackers) as unique_ips,
            (SELECT COUNT(*) FROM login_attempts) as login_attempts,
            (SELECT COUNT(*) FROM downloads) as files
    """)


def get_attacks_by_country():
    rows = query("""
        SELECT a.country, COUNT(e.id) as attacks
        FROM events e
        JOIN attackers a ON a.ip = e.src_ip
        WHERE e.event_type = 'cowrie.session.connect'
          AND a.country IS NOT NULL
        GROUP BY a.country
        ORDER BY attacks DESC
    """)
    return [(r['country'], r['attacks']) for r in rows]


def get_attacks_timeline(hours=24):
    rows = query("""
        SELECT 
            strftime('%Y-%m-%d %H:00', timestamp) as hour,
            COUNT(*) as attacks
        FROM events
        WHERE event_type = 'cowrie.session.connect'
          AND timestamp > datetime('now', ?)
        GROUP BY hour
        ORDER BY hour
    """, (f'-{hours} hours',))
    return [(r['hour'], r['attacks']) for r in rows]


def get_downloads():
    return query("""
        SELECT * FROM downloads
        ORDER BY size DESC NULLS LAST
    """)


def get_commands_by_ip():
    rows = query("""
        SELECT src_ip, command
        FROM commands
        ORDER BY timestamp
    """)
    by_ip = defaultdict(list)
    for r in rows:
        by_ip[r['src_ip']].append(r['command'])
    return dict(by_ip)


def detect_patterns():
    commands_by_ip = get_commands_by_ip()
    ip_counts = get_ip_counts()
    attackers = get_attackers()
    
    patterns = defaultdict(list)
    for ip, cmds in commands_by_ip.items():
        if len(cmds) < 2:
            continue
        signature = tuple(c[:80].strip() for c in cmds[:3])
        patterns[signature].append({
            'ip': ip,
            'country': attackers.get(ip, {}).get('country', '?'),
            'attacks': ip_counts.get(ip, 0)
        })
    
    result = []
    for sig, ips in patterns.items():
        if len(ips) >= 2:
            result.append({
                'signature': list(sig),
                'attackers': ips,
                'unique_ips': len(ips),
                'total_attacks': sum(x['attacks'] for x in ips)
            })
    result.sort(key=lambda x: x['unique_ips'], reverse=True)
    return result


def parse_tty_sessions():
    if not os.path.exists(TTY_DIR):
        return []
    
    rows = query("SELECT * FROM tty_mapping")
    mapping = {r['tty_filename']: r for r in rows}
    
    attackers = get_attackers()
    sessions = []
    
    for filename in os.listdir(TTY_DIR):
        filepath = os.path.join(TTY_DIR, filename)
        if not os.path.isfile(filepath):
            continue
        
        stat = os.stat(filepath)
        m = mapping.get(filename)
        
        if m:
            src_ip = m['src_ip']
            country = attackers.get(src_ip, {}).get('country', '?')
            sessions.append({
                'session_id': filename,
                'size_kb': round(stat.st_size / 1024, 2),
                'modified': stat.st_mtime,
                'duration_log': m['duration'] or 0,
                'src_ip': src_ip,
                'country': country,
                'session_id_short': m['session_id'],
            })
        else:
            sessions.append({
                'session_id': filename,
                'size_kb': round(stat.st_size / 1024, 2),
                'modified': stat.st_mtime,
                'duration_log': 0,
                'src_ip': 'unknown',
                'country': '?',
                'session_id_short': None,
            })
    
    sessions.sort(key=lambda x: x['modified'], reverse=True)
    return sessions
    
def get_downloads_with_iocs():
    rows = query("SELECT * FROM downloads ORDER BY size DESC NULLS LAST")
    
    for r in rows:
        sha = r['sha256']
        filepath = os.path.join(DOWNLOADS_DIR, sha)
        
        if os.path.exists(filepath):
            r['exists'] = True
            r['iocs'] = extract_iocs_from_file(filepath)
            
            if not r.get('file_type'):
                with open(filepath, 'rb') as f:
                    magic = f.read(8)
                r['file_type'] = detect_type(magic)
        else:
            r['exists'] = False
            r['iocs'] = {}
        
        if r.get('vt_malicious') is not None:
            r['vt'] = {
                'malicious': r['vt_malicious'],
                'total': r['vt_total'],
                'threat_label': r['vt_threat'],
                'family': r['vt_family'].split(',') if r['vt_family'] else [],
            }
        else:
            r['vt'] = None
    
    return rows


def detect_type(magic_bytes):
    if magic_bytes[:7] == b'ssh-rsa':
        return 'SSH public key'
    if magic_bytes[:4] == b'\x7fELF':
        return 'ELF binary (Linux)'
    if magic_bytes[:2] == b'#!':
        return 'Shell script'
    if magic_bytes[:2] == b'MZ':
        return 'Windows PE'
    if magic_bytes[:4] == b'PK\x03\x04':
        return 'ZIP/JAR'
    return 'Unknown/Text'


def extract_iocs_from_file(filepath):
    import re
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        text = data.decode('utf-8', errors='ignore')
    except Exception:
        return {}
    
    urls = re.findall(r'https?://[a-zA-Z0-9][a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=]{4,200}', text)
    urls = [u for u in urls if len(u) < 100 and u.count('http') == 1]
    
    ips = re.findall(r'(?<![\d.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\d.])', text)
    ips = [ip for ip in ips if not ip.startswith(('0.', '127.', '255.', '10.', '192.168.', '169.254.', '224.'))
           and all(int(o) < 256 for o in ip.split('.'))]
    
    domains = re.findall(
        r'(?:^|[\s\'"<>])([a-zA-Z0-9][a-zA-Z0-9\-]{1,62}(?:\.[a-zA-Z0-9\-]{1,62}){0,3}\.(?:com|net|org|ru|cn|onion|io|su|biz|info|xyz|top))(?:[\s\'"<>/]|$)',
        text
    )
    domains = [d for d in domains if d.count('.') >= 1 and len(d) > 5]
    
    webhooks = re.findall(r'https://discord(?:app)?\.com/api/webhooks/\d+/[\w\-]+', text)
    
    return {
        'urls': sorted(set(urls))[:15],
        'ips': sorted(set(ips))[:15],
        'domains': sorted(set(domains))[:15],
        'discord_webhooks': list(set(webhooks)),
    }


def parse_tty_sessions():
    if not os.path.exists(TTY_DIR):
        return []
    
    rows = query("SELECT * FROM tty_mapping")
    mapping = {r['tty_filename']: r for r in rows}
    
    attackers = get_attackers()
    sessions = []
    
    for filename in os.listdir(TTY_DIR):
        filepath = os.path.join(TTY_DIR, filename)
        if not os.path.isfile(filepath):
            continue
        
        stat = os.stat(filepath)
        m = mapping.get(filename)
        
        if m:
            src_ip = m['src_ip']
            country = attackers.get(src_ip, {}).get('country', '?')
            sessions.append({
                'session_id': filename,
                'size_kb': round(stat.st_size / 1024, 2),
                'modified': stat.st_mtime,
                'duration_log': m['duration'] or 0,
                'src_ip': src_ip,
                'country': country,
                'session_id_short': m['session_id'],
            })
        else:
            sessions.append({
                'session_id': filename,
                'size_kb': round(stat.st_size / 1024, 2),
                'modified': stat.st_mtime,
                'duration_log': 0,
                'src_ip': 'unknown',
                'country': '?',
                'session_id_short': None,
            })
    
    sessions.sort(key=lambda x: x['modified'], reverse=True)
    return sessions

def get_all_data():
    attackers = get_attackers()
    ip_counts = get_ip_counts()
    
    return {
        'attackers': attackers,
        'ip_count': ip_counts,
        'top_passwords': get_top_passwords(20),
        'top_usernames': get_top_usernames(20),
        'downloads': get_downloads_with_iocs(),
        'patterns': detect_patterns(),
        'tty_sessions': parse_tty_sessions(),
        'timeline': get_attacks_timeline(24),
        'attacks_by_country': get_attacks_by_country(),
        'summary': get_summary(),
    }


if __name__ == "__main__":
    import time
    start = time.time()
    data = get_all_data()
    print(f"Attackers: {len(data['attackers'])}")
    print(f"Total attacks: {sum(data['ip_count'].values())}")
    print(f"Passwords: {len(data['passwords'])}")
    print(f"Downloads: {len(data['downloads'])}")
    print(f"Patterns: {len(data['patterns'])}")
    print(f"Time: {round(time.time() - start, 3)}s")
