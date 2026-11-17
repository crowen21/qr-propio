import sqlite3
from contextlib import contextmanager

from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    pw_hash TEXT NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0,
    plan TEXT NOT NULL DEFAULT 'free',
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS qrs (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    target TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'ok',      -- 'ok' | 'flagged'
    flag_reason TEXT,
    scans INTEGER NOT NULL DEFAULT 0,
    last_scan_at INTEGER,
    expires_at INTEGER,                     -- NULL = no expira (plan gratuito inicial)
    created_at INTEGER NOT NULL,
    checked_at INTEGER,
    logo BLOB,                              -- PNG ya saneado; solo plan 'pro'
    kind TEXT NOT NULL DEFAULT 'url',
    data TEXT                               -- JSON con los campos del tipo
);
CREATE TABLE IF NOT EXISTS identities (
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (provider, subject)
);
CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    qr_id INTEGER,
    product TEXT NOT NULL,                  -- 'qr' | 'pro_mes' | 'pro_anual'
    amount INTEGER NOT NULL,
    commerce_order TEXT NOT NULL UNIQUE,
    flow_token TEXT,
    status TEXT NOT NULL DEFAULT 'pending', -- pending | paid | rejected | cancelled
    created_at INTEGER NOT NULL,
    paid_at INTEGER
);
CREATE TABLE IF NOT EXISTS scans (
    qr_id INTEGER NOT NULL REFERENCES qrs(id) ON DELETE CASCADE,
    ts INTEGER NOT NULL                      -- solo la hora del escaneo: no se guarda quién escanea
);
CREATE INDEX IF NOT EXISTS scans_qr_ts ON scans(qr_id, ts);
CREATE TABLE IF NOT EXISTS blocklist (host TEXT PRIMARY KEY);
"""


@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init():
    with connect() as c:
        c.execute("PRAGMA journal_mode = WAL")
        c.executescript(SCHEMA)
        cols = {r["name"] for r in c.execute("PRAGMA table_info(qrs)")}
        for col, ddl in (("logo", "BLOB"), ("kind", "TEXT NOT NULL DEFAULT 'url'"), ("data", "TEXT"),
                         ("paid", "INTEGER NOT NULL DEFAULT 0"), ("fg", "TEXT"), ("bg", "TEXT"),
                         ("frame", "TEXT"), ("logo_size", "TEXT")):
            if col not in cols:  # bases creadas con una versión anterior
                c.execute(f"ALTER TABLE qrs ADD COLUMN {col} {ddl}")
        ucols = {r["name"] for r in c.execute("PRAGMA table_info(users)")}
        for col, ddl in (("plan_until", "INTEGER"), ("reminded_at", "INTEGER"), ("terms_at", "INTEGER")):
            if col not in ucols:
                c.execute(f"ALTER TABLE users ADD COLUMN {col} {ddl}")
