import os
import pymysql
from pymysql.constants import CLIENT
from dotenv import load_dotenv

load_dotenv()

DB_HOST = os.getenv('MYSQL_HOST', 'localhost')
DB_PORT = int(os.getenv('MYSQL_PORT', 3306))
DB_USER = os.getenv('MYSQL_USER', 'root')
DB_PASSWORD = os.getenv('MYSQL_PASSWORD', '')
DB_NAME = os.getenv('MYSQL_DATABASE', 'scam_spotter_db')

def get_connection():
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )

def init_db():
    conn = pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
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

if __name__ == '__main__':
    init_db()
    print("Database and tables initialized successfully!")
