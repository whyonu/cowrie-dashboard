import sqlite3
import os
from contextlib import contextmanager
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv('DB_PATH', '/opt/honeypot/bot/honeypot.db')


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def query(sql, params=None):
    with get_db() as conn:
        cursor = conn.execute(sql, params or [])
        return [dict(row) for row in cursor.fetchall()]


def query_one(sql, params=None):
    with get_db() as conn:
        cursor = conn.execute(sql, params or [])
        row = cursor.fetchone()
        return dict(row) if row else None


def execute(sql, params=None):
    with get_db() as conn:
        conn.execute(sql, params or [])


def execute_many(sql, params_list):
    with get_db() as conn:
        conn.executemany(sql, params_list)
