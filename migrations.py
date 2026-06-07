from database import get_db

MIGRATIONS = [
    ("001_create_attackers", """
        CREATE TABLE IF NOT EXISTS attackers (
            ip TEXT PRIMARY KEY,
            country TEXT,
            isp TEXT,
            lat REAL,
            lon REAL,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP
        )
    """),

    ("002_create_events", """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP NOT NULL,
            src_ip TEXT NOT NULL,
            event_type TEXT NOT NULL,
            session_id TEXT
        )
    """),

    ("003_create_logins", """
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP NOT NULL,
            src_ip TEXT NOT NULL,
            username TEXT,
            password TEXT,
            success INTEGER,
            session_id TEXT
        )
    """),

    ("004_create_commands", """
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP NOT NULL,
            src_ip TEXT NOT NULL,
            command TEXT NOT NULL,
            session_id TEXT
        )
    """),

    ("005_create_downloads", """
        CREATE TABLE IF NOT EXISTS downloads (
            sha256 TEXT PRIMARY KEY,
            first_seen TIMESTAMP,
            src_ip TEXT,
            url TEXT,
            size INTEGER,
            file_type TEXT,
            vt_malicious INTEGER,
            vt_total INTEGER,
            vt_threat TEXT,
            vt_family TEXT,
            bazaar_signature TEXT,
            iocs_json TEXT
        )
    """),

    ("006_create_parser_state", """
        CREATE TABLE IF NOT EXISTS parser_state (
            log_file TEXT PRIMARY KEY,
            last_position INTEGER NOT NULL DEFAULT 0,
            last_updated TIMESTAMP
        )
    """),

    ("007_create_migrations_table", """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            name TEXT PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """),

    ("008_create_indexes", """
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip);
        CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
        CREATE INDEX IF NOT EXISTS idx_logins_timestamp ON login_attempts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_logins_ip ON login_attempts(src_ip);
        CREATE INDEX IF NOT EXISTS idx_commands_ip ON commands(src_ip);
        CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id);
    """),

    ("009_create_tty_mapping", """
        CREATE TABLE IF NOT EXISTS tty_mapping (
            tty_filename TEXT PRIMARY KEY,
            src_ip TEXT NOT NULL,
            session_id TEXT,
            duration REAL,
            timestamp TIMESTAMP
        )
    """),
]


def run_migrations():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                name TEXT PRIMARY KEY,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor = conn.execute("SELECT name FROM schema_migrations")
        applied = {row['name'] for row in cursor.fetchall()}

        for name, sql in MIGRATIONS:
            if name in applied:
                print(f"  ⏭  {name} уже применена")
                continue

            print(f"Применяю {name}...")
            conn.executescript(sql)
            conn.execute(
                "INSERT INTO schema_migrations (name) VALUES (?)",
                (name,)
            )
            print(f"  ✅ {name}")

        print("\n🎉 Все миграции применены!")


if __name__ == "__main__":
    print("Запуск миграций...\n")
    run_migrations()
