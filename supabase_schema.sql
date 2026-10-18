-- ====================================================================
-- Scam Spotter — Supabase PostgreSQL Database Schema
-- Paste and run this script in your Supabase SQL Editor:
-- https://supabase.com/dashboard/project/_/sql
-- ====================================================================

-- 1. Users Table (Account & Authentication)
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(191) NOT NULL UNIQUE,
    name VARCHAR(120) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. User Sessions Table (Persistent Active Logins & Token Verification)
CREATE TABLE IF NOT EXISTS user_sessions (
    session_id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_active TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45) NULL,
    user_agent VARCHAR(255) NULL,
    is_active BOOLEAN DEFAULT TRUE
);

-- 3. Scan Records Table (Persistent Threat Analysis History)
CREATE TABLE IF NOT EXISTS scan_records (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NULL REFERENCES users(id) ON DELETE SET NULL,
    session_id VARCHAR(64) NULL,
    scan_type VARCHAR(32) NOT NULL DEFAULT 'TEXT_MESSAGE',
    content_preview TEXT NOT NULL,
    risk_score INT NOT NULL,
    risk_level VARCHAR(16) NOT NULL,
    headline VARCHAR(255) NULL,
    rules_fired_json JSONB NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. Performance Indexes
CREATE INDEX IF NOT EXISTS idx_scan_records_user ON scan_records(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_records_session ON scan_records(session_id);
CREATE INDEX IF NOT EXISTS idx_scan_records_created ON scan_records(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_sessions_lookup ON user_sessions(session_id, is_active);
