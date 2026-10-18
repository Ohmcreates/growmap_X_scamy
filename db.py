"""
Scam Spotter — Multi-Database Adapter
Seamlessly connects to:
1. Supabase / PostgreSQL (Production cloud via DATABASE_URL / SUPABASE_DB_URL)
2. MySQL (Development / self-hosted via MYSQL_HOST)
3. SQLite (Zero-config local fallback via scam_spotter.db)
"""

import os
import re
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv('DATABASE_URL') or os.getenv('SUPABASE_DB_URL')
DB_TYPE = 'postgres' if DATABASE_URL and ('postgres://' in DATABASE_URL or 'postgresql://' in DATABASE_URL) else ('mysql' if os.getenv('MYSQL_HOST') else 'sqlite')

# Normalize postgres:// to postgresql:// for standard SQLAlchemy/psycopg2 compliance
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

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
        from pymysql.constants import CLIENT
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
        # SQLite zero-configuration local fallback
        import sqlite3
        db_path = os.path.join(os.path.dirname(__file__), 'scam_spotter.db')
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        conn.isolation_level = None # autocommit
        return conn

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
        # SQLite
        import sqlite3
        db_path = os.path.join(os.path.dirname(__file__), 'scam_spotter.db')
        conn = sqlite3.connect(db_path)
        try:
            cur = conn.cursor()
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
            conn.commit()
        finally:
            conn.close()

if __name__ == '__main__':
    init_db()
    print(f"Database ({DB_TYPE}) and tables initialized successfully!")
