"""
Scam Spotter — Multi-Database Adapter
Supports:
1. SQLite (Default zero-config embedded database via scam_spotter.db)
2. Supabase / PostgreSQL (Production cloud via DATABASE_URL / SUPABASE_DB_URL)
3. MySQL (Optional self-hosted via MYSQL_HOST)
"""

import os
import sqlite3
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv('DATABASE_URL') or os.getenv('SUPABASE_DB_URL')

def _is_valid_postgres_url(url: str | None) -> bool:
    if not url or not isinstance(url, str):
        return False
    u = url.strip()
    if not (u.startswith('postgres://') or u.startswith('postgresql://')):
        return False
    # Avoid picking up template placeholders
    placeholder_tokens = ['[YOUR-', '[PROJECT-REF]', '<', 'placeholder', 'dummy']
    return not any(token in u for token in placeholder_tokens)

IS_POSTGRES = _is_valid_postgres_url(DATABASE_URL)

# Default to SQLite unless explicitly forced to postgres or mysql
explicit_db = os.getenv('DB_TYPE', '').lower()
if explicit_db == 'mysql' and os.getenv('MYSQL_HOST'):
    DB_TYPE = 'mysql'
elif explicit_db == 'postgres' and IS_POSTGRES:
    DB_TYPE = 'postgres'
elif IS_POSTGRES and os.getenv('USE_POSTGRES'):
    DB_TYPE = 'postgres'
elif os.getenv('USE_MYSQL') and os.getenv('MYSQL_HOST'):
    DB_TYPE = 'mysql'
else:
    # Primary default is SQLite (zero-config, high performance, file-based)
    DB_TYPE = 'sqlite'

# Normalize postgres:// to postgresql:// for standard SQLAlchemy/psycopg2 compliance
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

class SQLiteCursorWrapper:
    """Wraps an sqlite3.Cursor to provide MySQL/Postgres compatible context manager,
    placeholder translation (%s -> ?), and dictionary row formatting."""
    def __init__(self, cursor):
        self._cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self._cursor.close()
        except Exception:
            pass

    def execute(self, sql, params=None):
        sql_translated = sql.replace('%s', '?')
        if params is None:
            return self._cursor.execute(sql_translated)
        return self._cursor.execute(sql_translated, params)

    def executemany(self, sql, seq_of_params):
        sql_translated = sql.replace('%s', '?')
        return self._cursor.executemany(sql_translated, seq_of_params)

    def fetchone(self):
        row = self._cursor.fetchone()
        if row is None:
            return None
        return dict(row) if hasattr(row, 'keys') else row

    def fetchall(self):
        rows = self._cursor.fetchall()
        if not rows:
            return []
        return [dict(r) if hasattr(r, 'keys') else r for r in rows]

    def fetchmany(self, size=None):
        rows = self._cursor.fetchmany(size) if size else self._cursor.fetchmany()
        if not rows:
            return []
        return [dict(r) if hasattr(r, 'keys') else r for r in rows]

    def close(self):
        try:
            return self._cursor.close()
        except Exception:
            pass

    def __getattr__(self, name):
        return getattr(self._cursor, name)

class SQLiteConnectionWrapper:
    """Wraps an sqlite3.Connection with auto-commit, WAL mode, and dict cursor."""
    def __init__(self, conn):
        self._conn = conn

    def cursor(self):
        return SQLiteCursorWrapper(self._conn.cursor())

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def close(self):
        return self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.rollback()
        else:
            self.commit()

    def __getattr__(self, name):
        return getattr(self._conn, name)

def get_connection():
    """Returns an active database connection with dictionary-like cursor support."""
    if DB_TYPE == 'postgres':
        import psycopg2
        from psycopg2.extras import RealDictCursor
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        conn.autocommit = True
        return conn

    elif DB_TYPE == 'mysql':
        import pymysql
        return pymysql.connect(
            host=os.getenv('MYSQL_HOST', 'localhost'),
            port=int(os.getenv('MYSQL_PORT', 3306)),
            user=os.getenv('MYSQL_USER', 'root'),
            password=os.getenv('MYSQL_PASSWORD', ''),
            database=os.getenv('MYSQL_DATABASE', 'scam_spotter_db'),
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True
        )

    else:
        # SQLite zero-configuration local embedded database
        db_path = os.getenv('SQLITE_PATH') or os.path.join(os.path.dirname(__file__), 'scam_spotter.db')
        raw_conn = sqlite3.connect(db_path, check_same_thread=False)
        raw_conn.row_factory = sqlite3.Row
        # Enable WAL mode for high concurrency and performance
        raw_conn.execute("PRAGMA journal_mode=WAL;")
        raw_conn.execute("PRAGMA foreign_keys=ON;")
        raw_conn.isolation_level = None # autocommit
        return SQLiteConnectionWrapper(raw_conn)

def init_db():
    """Initializes schema and tables for users, sessions, and threat scan records."""
    if DB_TYPE == 'postgres':
        import psycopg2
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = True
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id VARCHAR(36) PRIMARY KEY,
                        email VARCHAR(191) NOT NULL UNIQUE,
                        name VARCHAR(120) NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS user_sessions (
                        session_id VARCHAR(64) PRIMARY KEY,
                        user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        ip_address VARCHAR(45) NULL,
                        user_agent VARCHAR(255) NULL,
                        is_active BOOLEAN DEFAULT TRUE
                    );
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS scan_records (
                        id VARCHAR(36) PRIMARY KEY,
                        user_id VARCHAR(36) NULL,
                        session_id VARCHAR(64) NULL,
                        scan_type VARCHAR(32) NOT NULL DEFAULT 'TEXT_MESSAGE',
                        content_preview TEXT NOT NULL,
                        risk_score INT NOT NULL,
                        risk_level VARCHAR(16) NOT NULL,
                        headline VARCHAR(255) NULL,
                        rules_fired_json JSONB NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE INDEX IF NOT EXISTS idx_scan_user ON scan_records(user_id);
                    CREATE INDEX IF NOT EXISTS idx_scan_session ON scan_records(session_id);
                    CREATE INDEX IF NOT EXISTS idx_scan_created ON scan_records(created_at);
                """)
        finally:
            conn.close()

    elif DB_TYPE == 'mysql':
        import pymysql
        DB_NAME = os.getenv('MYSQL_DATABASE', 'scam_spotter_db')
        conn = pymysql.connect(
            host=os.getenv('MYSQL_HOST', 'localhost'),
            port=int(os.getenv('MYSQL_PORT', 3306)),
            user=os.getenv('MYSQL_USER', 'root'),
            password=os.getenv('MYSQL_PASSWORD', ''),
            charset='utf8mb4',
            autocommit=True
        )
        try:
            with conn.cursor() as cur:
                cur.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
                cur.execute(f"USE `{DB_NAME}`;")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id VARCHAR(36) PRIMARY KEY,
                        email VARCHAR(191) NOT NULL UNIQUE,
                        name VARCHAR(120) NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS user_sessions (
                        session_id VARCHAR(64) PRIMARY KEY,
                        user_id VARCHAR(36) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        ip_address VARCHAR(45) NULL,
                        user_agent VARCHAR(255) NULL,
                        is_active BOOLEAN DEFAULT TRUE,
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS scan_records (
                        id VARCHAR(36) PRIMARY KEY,
                        user_id VARCHAR(36) NULL,
                        session_id VARCHAR(64) NULL,
                        scan_type VARCHAR(32) NOT NULL DEFAULT 'TEXT_MESSAGE',
                        content_preview TEXT NOT NULL,
                        risk_score INT NOT NULL,
                        risk_level VARCHAR(16) NOT NULL,
                        headline VARCHAR(255) NULL,
                        rules_fired_json JSON NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        INDEX idx_user_id (user_id),
                        INDEX idx_session_id (session_id),
                        INDEX idx_created (created_at)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """)
        finally:
            conn.close()

    else:
        # SQLite zero-configuration default
        db_path = os.getenv('SQLITE_PATH') or os.path.join(os.path.dirname(__file__), 'scam_spotter.db')
        conn = sqlite3.connect(db_path)
        try:
            cur = conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA foreign_keys=ON;")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS user_sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT NULL,
                    user_agent TEXT NULL,
                    is_active INTEGER DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan_records (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NULL,
                    session_id TEXT NULL,
                    scan_type TEXT NOT NULL DEFAULT 'TEXT_MESSAGE',
                    content_preview TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    headline TEXT NULL,
                    rules_fired_json TEXT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_records_user ON scan_records(user_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_records_session ON scan_records(session_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_records_created ON scan_records(created_at DESC);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_user_sessions_lookup ON user_sessions(session_id, is_active);")
            conn.commit()
        finally:
            conn.close()

if __name__ == '__main__':
    init_db()
    print(f"Database ({DB_TYPE}) initialized successfully!")
