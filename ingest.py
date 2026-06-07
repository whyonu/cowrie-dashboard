import json
import os
import glob
import time
from datetime import datetime
from database import get_db, query_one, execute


LOG_GLOB = os.getenv('LOG_GLOB', '/opt/honeypot/cowrie-data/cowrie.json*')


def get_last_position(log_file):
    """Get the byte position where we last stopped reading"""
    row = query_one(
        "SELECT last_position FROM parser_state WHERE log_file = ?",
        (log_file,)
    )
    return row['last_position'] if row else 0


def save_position(log_file, position):
    """Save the new byte position"""
    with get_db() as conn:
        conn.execute("""
            INSERT INTO parser_state (log_file, last_position, last_updated)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(log_file) DO UPDATE SET
                last_position = excluded.last_position,
                last_updated = CURRENT_TIMESTAMP
        """, (log_file, position))


def process_event(conn, event):
    """
    Process a single event from the log.
    Routes data into the appropriate tables based on event type.
    """
    eventid = event.get('eventid')
    timestamp = event.get('timestamp')
    src_ip = event.get('src_ip')
    session = event.get('session')

    if not src_ip or not timestamp:
        return

    # Base events table — record every event
    conn.execute("""
        INSERT INTO events (timestamp, src_ip, event_type, session_id)
        VALUES (?, ?, ?, ?)
    """, (timestamp, src_ip, eventid, session))

    # Upsert attacker (update last_seen, create on first appearance)
    conn.execute("""
        INSERT INTO attackers (ip, first_seen, last_seen)
        VALUES (?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET last_seen = excluded.last_seen
    """, (src_ip, timestamp, timestamp))

    # Type-specific tables
    if eventid in ('cowrie.login.success', 'cowrie.login.failed'):
        success = 1 if eventid == 'cowrie.login.success' else 0
        conn.execute("""
            INSERT INTO login_attempts
            (timestamp, src_ip, username, password, success, session_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            timestamp, src_ip,
            event.get('username'), event.get('password'),
            success, session
        ))

    elif eventid == 'cowrie.command.input':
        cmd = event.get('input')
        if cmd:
            conn.execute("""
                INSERT INTO commands (timestamp, src_ip, command, session_id)
                VALUES (?, ?, ?, ?)
            """, (timestamp, src_ip, cmd, session))

    elif eventid == 'cowrie.session.file_download':
        sha = event.get('shasum')
        if sha:
            conn.execute("""
                INSERT OR IGNORE INTO downloads
                (sha256, first_seen, src_ip, url)
                VALUES (?, ?, ?, ?)
            """, (sha, timestamp, src_ip, event.get('url')))

    elif eventid == 'cowrie.log.closed':
        ttylog = event.get('ttylog', '')
        if ttylog:
            tty_filename = ttylog.split('/')[-1]
            conn.execute("""
                INSERT OR REPLACE INTO tty_mapping
                (tty_filename, src_ip, session_id, duration, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (
                tty_filename, src_ip, session,
                float(event.get('duration', 0)),
                timestamp
            ))


def ingest_file(log_file):
    last_pos = get_last_position(log_file)
    file_size = os.path.getsize(log_file)

    if last_pos >= file_size:
        return 0

    new_events = 0
    errors = 0

    with open(log_file, 'r') as f:
        f.seek(last_pos)

        with get_db() as conn:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    process_event(conn, event)
                    new_events += 1
                except json.JSONDecodeError:
                    errors += 1
                except Exception as e:
                    errors += 1
                    print(f"  ⚠️ Error: {e}")

        new_pos = f.tell()

    save_position(log_file, new_pos)
    return new_events


def ingest_all():
    """Parse all log files sequentially"""
    log_files = sorted(glob.glob(LOG_GLOB))
    if not log_files:
        print("❌ No log files found!")
        return

    total = 0
    for log_file in log_files:
        print(f"  📄 {os.path.basename(log_file)}...", end=" ", flush=True)
        count = ingest_file(log_file)
        print(f"+{count} new events")
        total += count

    print(f"\n🎉 Total processed: {total} events")


if __name__ == "__main__":
    print("🚀 Starting ingester...\n")
    start = time.time()
    ingest_all()
    print(f"⏱ Time: {round(time.time() - start, 2)}s")
