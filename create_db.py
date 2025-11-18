#!/usr/bin/env python3
"""
Database Setup Script
Creates all necessary tables and an initial admin user for the authentication system.

Usage:
    python create_db.py

Requirements:
    pip install psycopg2-binary argon2-cffi python-dotenv
"""

import os
import sys
import psycopg2
from psycopg2 import sql
from argon2 import PasswordHasher
from argon2.exceptions import HashingError
from datetime import datetime
from getpass import getpass
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database configuration
DB_CONFIG = {
    'dbname': os.getenv('DB_NAME', 'creative_ai_db'),
    'user': os.getenv('DB_USER', 'postgres'),
    'password': os.getenv('DB_PASSWORD', 'postgres'),
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': os.getenv('DB_PORT', '5432')
}

# SQL for creating all tables
SQL_CREATE_TABLES = """
-- Drop existing tables if they exist (careful in production!)
DROP TABLE IF EXISTS flowcharts CASCADE;
DROP TABLE IF EXISTS notifications CASCADE;
DROP TABLE IF EXISTS team_invitations CASCADE;
DROP TABLE IF EXISTS idea_team_assignments CASCADE;
DROP TABLE IF EXISTS idea_versions CASCADE;
DROP TABLE IF EXISTS idea_contributors CASCADE;
DROP TABLE IF EXISTS generated_images CASCADE;
DROP TABLE IF EXISTS ideas CASCADE;
DROP TABLE IF EXISTS notes CASCADE;
DROP TABLE IF EXISTS drive_files CASCADE;
DROP TABLE IF EXISTS drive_folders CASCADE;
DROP TABLE IF EXISTS team_members CASCADE;
DROP TABLE IF EXISTS teams CASCADE;
DROP TABLE IF EXISTS messages CASCADE;
DROP TABLE IF EXISTS security_incidents CASCADE;
DROP TABLE IF EXISTS backup_schedules CASCADE;
DROP TABLE IF EXISTS drive_backups CASCADE;
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS email_verification_tokens CASCADE;
DROP TABLE IF EXISTS password_reset_tokens CASCADE;
DROP TABLE IF EXISTS user_sessions CASCADE;
DROP TABLE IF EXISTS user_api_keys CASCADE;
DROP TABLE IF EXISTS user_mfa CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    encryption_key TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    account_status VARCHAR(50) DEFAULT 'pending_verification',
    email_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    CONSTRAINT chk_account_status CHECK (account_status IN ('active', 'suspended', 'pending_verification', 'deleted'))
);

-- User MFA table
CREATE TABLE user_mfa (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mfa_method VARCHAR(20) DEFAULT 'totp',
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_verified BOOLEAN DEFAULT FALSE,
    totp_secret_encrypted TEXT,
    backup_codes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    CONSTRAINT chk_mfa_method CHECK (mfa_method IN ('totp', 'email')),
    UNIQUE(user_id, mfa_method)
);

-- User API Keys table (double-encrypted storage for GEMINI_API_KEY and AIMLAPI_KEY)
CREATE TABLE user_api_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    api_key_type VARCHAR(50) NOT NULL,
    -- Layer 1: API key encrypted with random AES key
    encrypted_key TEXT NOT NULL,
    iv1 VARCHAR(64) NOT NULL,
    tag1 VARCHAR(64) NOT NULL,
    -- Layer 2: Random AES key encrypted with user's encryption key
    encrypted_key_key TEXT NOT NULL,
    iv2 VARCHAR(64) NOT NULL,
    tag2 VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    CONSTRAINT chk_api_key_type CHECK (api_key_type IN ('gemini', 'aimlapi')),
    UNIQUE(user_id, api_key_type)
);

-- User sessions table
CREATE TABLE user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    refresh_token VARCHAR(255) UNIQUE,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Password reset tokens table
CREATE TABLE password_reset_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    ip_address INET
);

-- Email verification tokens table
CREATE TABLE email_verification_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    verified_at TIMESTAMP
);

-- Audit log table
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    status VARCHAR(20) NOT NULL,
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_status CHECK (status IN ('success', 'failed'))
);

-- Messages table
CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject VARCHAR(255),
    content_sender TEXT NOT NULL,
    content_receiver TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    read_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_by_sender BOOLEAN DEFAULT FALSE,
    deleted_by_receiver BOOLEAN DEFAULT FALSE,
    CONSTRAINT chk_different_users CHECK (sender_id != receiver_id)
);

-- Teams table
CREATE TABLE teams (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    team_key_encrypted TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Team members table
CREATE TABLE team_members (
    id SERIAL PRIMARY KEY,
    team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(20) NOT NULL,
    team_key_encrypted TEXT NOT NULL,
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    added_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    is_active BOOLEAN DEFAULT TRUE,
    CONSTRAINT chk_team_role CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    UNIQUE(team_id, user_id)
);

-- Drive folders table
CREATE TABLE drive_folders (
    id SERIAL PRIMARY KEY,
    name_encrypted TEXT NOT NULL,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    parent_folder_id INTEGER REFERENCES drive_folders(id) ON DELETE CASCADE,
    encryption_iv VARCHAR(64) NOT NULL,
    encryption_tag VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN DEFAULT FALSE,
    CONSTRAINT chk_folder_ownership CHECK (
        (team_id IS NULL AND owner_id IS NOT NULL) OR
        (team_id IS NOT NULL)
    )
);

-- Drive files table
CREATE TABLE drive_files (
    id SERIAL PRIMARY KEY,
    filename_encrypted TEXT NOT NULL,
    file_path VARCHAR(500) NOT NULL UNIQUE,
    file_size BIGINT NOT NULL,
    mime_type_encrypted TEXT NOT NULL,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    folder_id INTEGER REFERENCES drive_folders(id) ON DELETE SET NULL,
    encryption_iv VARCHAR(64) NOT NULL,
    encryption_tag VARCHAR(64) NOT NULL,
    checksum TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN DEFAULT FALSE,
    metadata_stripped BOOLEAN DEFAULT TRUE,
    CONSTRAINT chk_file_size CHECK (file_size > 0 AND file_size <= 10485760),
    CONSTRAINT chk_file_ownership CHECK (
        (team_id IS NULL AND owner_id IS NOT NULL) OR
        (team_id IS NOT NULL)
    )
);

-- Notes table
CREATE TABLE notes (
    id SERIAL PRIMARY KEY,
    title_encrypted TEXT NOT NULL,
    content_encrypted TEXT NOT NULL,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    folder_id INTEGER REFERENCES drive_folders(id) ON DELETE SET NULL,
    encryption_iv VARCHAR(64) NOT NULL,
    encryption_tag VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN DEFAULT FALSE,
    is_pinned BOOLEAN DEFAULT FALSE
);

-- Ideas table
CREATE TABLE ideas (
    id SERIAL PRIMARY KEY,
    title_encrypted TEXT NOT NULL,
    description_encrypted TEXT,
    content_encrypted TEXT NOT NULL,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    status VARCHAR(20) DEFAULT 'draft',
    encryption_iv VARCHAR(64) NOT NULL,
    encryption_tag VARCHAR(64) NOT NULL,
    -- Voice generation fields
    voice_file_path VARCHAR(500),
    voice_metadata TEXT,
    -- Video generation fields
    video_url TEXT,
    video_status VARCHAR(20),
    video_task_id VARCHAR(255),
    video_prompt_encrypted TEXT,
    video_duration INTEGER,
    video_aspect_ratio VARCHAR(10),
    video_generated_at TIMESTAMP,
    video_iv VARCHAR(64),
    video_tag VARCHAR(64),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN DEFAULT FALSE,
    is_pinned BOOLEAN DEFAULT FALSE,
    CONSTRAINT chk_idea_status CHECK (status IN ('draft', 'in_progress', 'review', 'completed', 'archived')),
    CONSTRAINT chk_video_status CHECK (video_status IS NULL OR video_status IN ('processing', 'completed', 'failed', 'error'))
);

-- Generated images table (AI image generation)
CREATE TABLE generated_images (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    prompt_encrypted TEXT NOT NULL,
    encryption_iv VARCHAR(64) NOT NULL,
    encryption_tag VARCHAR(64) NOT NULL,
    image_url TEXT NOT NULL,
    image_filename VARCHAR(500),
    style VARCHAR(50),
    aspect_ratio VARCHAR(10),
    model VARCHAR(100),
    original_prompt_hash VARCHAR(64),
    status VARCHAR(20) DEFAULT 'active',
    is_favorite BOOLEAN DEFAULT FALSE,
    is_deleted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_image_status CHECK (status IN ('active', 'archived', 'deleted'))
);

-- Idea contributors table
CREATE TABLE idea_contributors (
    id SERIAL PRIMARY KEY,
    idea_id INTEGER NOT NULL REFERENCES ideas(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(20) NOT NULL,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    added_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT chk_contributor_role CHECK (role IN ('editor', 'commenter', 'viewer')),
    UNIQUE(idea_id, user_id)
);

-- Idea versions table
CREATE TABLE idea_versions (
    id SERIAL PRIMARY KEY,
    idea_id INTEGER NOT NULL REFERENCES ideas(id) ON DELETE CASCADE,
    content_encrypted TEXT NOT NULL,
    encryption_iv VARCHAR(64) NOT NULL,
    encryption_tag VARCHAR(64) NOT NULL,
    version_number INTEGER NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    change_description_encrypted TEXT
);

-- Idea team assignments table
CREATE TABLE idea_team_assignments (
    id SERIAL PRIMARY KEY,
    idea_id INTEGER NOT NULL REFERENCES ideas(id) ON DELETE CASCADE,
    team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    assigned_by INTEGER NOT NULL REFERENCES users(id),
    assigned_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(idea_id, team_id)
);

-- Team invitations table
CREATE TABLE team_invitations (
    id SERIAL PRIMARY KEY,
    team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    inviter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    invitee_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(20) DEFAULT 'pending',
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    CONSTRAINT chk_invitation_status CHECK (status IN ('pending', 'accepted', 'rejected', 'cancelled'))
);

-- Notifications table
CREATE TABLE notifications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    priority VARCHAR(20) DEFAULT 'normal',
    related_type VARCHAR(50),
    related_id INTEGER,
    action_url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    read_at TIMESTAMP,
    expires_at TIMESTAMP,
    CONSTRAINT chk_notification_priority CHECK (priority IN ('low', 'normal', 'high', 'urgent'))
);

-- Flowcharts table for creative project planning
CREATE TABLE flowcharts (
    id SERIAL PRIMARY KEY,
    title_encrypted TEXT NOT NULL,
    description_encrypted TEXT,
    flowchart_data_encrypted TEXT NOT NULL,
    flowchart_type VARCHAR(20) DEFAULT 'mermaid',
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    folder_id INTEGER REFERENCES drive_folders(id) ON DELETE SET NULL,
    template_name VARCHAR(100),
    status VARCHAR(20) DEFAULT 'draft',
    encryption_iv VARCHAR(200) NOT NULL,
    encryption_tag VARCHAR(200) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN DEFAULT FALSE,
    is_pinned BOOLEAN DEFAULT FALSE,
    thumbnail_encrypted TEXT,
    node_notes TEXT DEFAULT '{}',
    CONSTRAINT chk_flowchart_type CHECK (flowchart_type IN ('mermaid', 'json', 'custom')),
    CONSTRAINT chk_flowchart_status CHECK (status IN ('draft', 'in_progress', 'review', 'completed', 'archived'))
);

-- Security incidents table
CREATE TABLE security_incidents (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    incident_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    ip_address INET,
    endpoint VARCHAR(255),
    input_sample TEXT,
    pattern_matched TEXT,
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_severity CHECK (severity IN ('low', 'medium', 'high', 'critical'))
);

-- Encrypted backups table
CREATE TABLE drive_backups (
    id SERIAL PRIMARY KEY,
    backup_name VARCHAR(255) NOT NULL,
    backup_type VARCHAR(20) NOT NULL,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    backup_path VARCHAR(500) NOT NULL UNIQUE,
    backup_size BIGINT NOT NULL,
    compressed_size BIGINT NOT NULL,
    encryption_iv VARCHAR(64) NOT NULL,
    encryption_tag VARCHAR(64) NOT NULL,
    checksum TEXT NOT NULL,
    file_count INTEGER NOT NULL DEFAULT 0,
    note_count INTEGER NOT NULL DEFAULT 0,
    idea_count INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(20) DEFAULT 'completed',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    is_deleted BOOLEAN DEFAULT FALSE,
    metadata_encrypted TEXT,
    CONSTRAINT chk_backup_type CHECK (backup_type IN ('full', 'incremental', 'differential')),
    CONSTRAINT chk_backup_status CHECK (status IN ('in_progress', 'completed', 'failed', 'expired')),
    CONSTRAINT chk_backup_ownership CHECK (
        (team_id IS NULL AND owner_id IS NOT NULL) OR
        (team_id IS NOT NULL)
    )
);

-- Backup schedules table
CREATE TABLE backup_schedules (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    schedule_name VARCHAR(255) NOT NULL,
    backup_type VARCHAR(20) NOT NULL,
    frequency VARCHAR(20) NOT NULL,
    retention_days INTEGER NOT NULL DEFAULT 30,
    is_active BOOLEAN DEFAULT TRUE,
    last_backup_at TIMESTAMP,
    next_backup_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_schedule_backup_type CHECK (backup_type IN ('full', 'incremental')),
    CONSTRAINT chk_schedule_frequency CHECK (frequency IN ('daily', 'weekly', 'monthly')),
    CONSTRAINT chk_schedule_ownership CHECK (
        (team_id IS NULL AND user_id IS NOT NULL) OR
        (team_id IS NOT NULL)
    )
);

-- Indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_is_admin ON users(is_admin);
CREATE INDEX idx_user_mfa_user_id ON user_mfa(user_id);
CREATE INDEX idx_user_api_keys_user_id ON user_api_keys(user_id);
CREATE INDEX idx_user_api_keys_type ON user_api_keys(api_key_type);
CREATE INDEX idx_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_sessions_token ON user_sessions(session_token);
CREATE INDEX idx_sessions_expires ON user_sessions(expires_at);
CREATE INDEX idx_password_reset_user ON password_reset_tokens(user_id);
CREATE INDEX idx_email_verify_user ON email_verification_tokens(user_id);
CREATE INDEX idx_audit_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_created ON audit_logs(created_at);
CREATE INDEX idx_messages_sender ON messages(sender_id);
CREATE INDEX idx_messages_receiver ON messages(receiver_id);
CREATE INDEX idx_messages_created ON messages(created_at);
CREATE INDEX idx_messages_is_read ON messages(is_read);
CREATE INDEX idx_security_incidents_user ON security_incidents(user_id);
CREATE INDEX idx_security_incidents_type ON security_incidents(incident_type);
CREATE INDEX idx_security_incidents_severity ON security_incidents(severity);
CREATE INDEX idx_security_incidents_created ON security_incidents(created_at);
CREATE INDEX idx_backups_owner ON drive_backups(owner_id);
CREATE INDEX idx_backups_team ON drive_backups(team_id);
CREATE INDEX idx_backups_created ON drive_backups(created_at);
CREATE INDEX idx_backups_status ON drive_backups(status);
CREATE INDEX idx_backup_schedules_user ON backup_schedules(user_id);
CREATE INDEX idx_backup_schedules_team ON backup_schedules(team_id);
CREATE INDEX idx_backup_schedules_next ON backup_schedules(next_backup_at);
CREATE INDEX idx_teams_owner ON teams(owner_id);
CREATE INDEX idx_team_members_team ON team_members(team_id);
CREATE INDEX idx_team_members_user ON team_members(user_id);
CREATE INDEX idx_folders_owner ON drive_folders(owner_id);
CREATE INDEX idx_folders_team ON drive_folders(team_id);
CREATE INDEX idx_folders_parent ON drive_folders(parent_folder_id);
CREATE INDEX idx_files_owner ON drive_files(owner_id);
CREATE INDEX idx_files_team ON drive_files(team_id);
CREATE INDEX idx_files_folder ON drive_files(folder_id);
CREATE INDEX idx_files_created ON drive_files(created_at);
CREATE INDEX idx_notes_owner ON notes(owner_id);
CREATE INDEX idx_notes_team ON notes(team_id);
CREATE INDEX idx_notes_folder ON notes(folder_id);
CREATE INDEX idx_notes_pinned ON notes(is_pinned);
CREATE INDEX idx_ideas_owner ON ideas(owner_id);
CREATE INDEX idx_ideas_team ON ideas(team_id);
CREATE INDEX idx_ideas_status ON ideas(status);
CREATE INDEX idx_ideas_video_status ON ideas(video_status);
CREATE INDEX idx_generated_images_user ON generated_images(user_id);
CREATE INDEX idx_generated_images_created ON generated_images(created_at);
CREATE INDEX idx_generated_images_status ON generated_images(status);
CREATE INDEX idx_generated_images_is_favorite ON generated_images(is_favorite);
CREATE INDEX idx_idea_contributors_idea ON idea_contributors(idea_id);
CREATE INDEX idx_idea_contributors_user ON idea_contributors(user_id);
CREATE INDEX idx_idea_versions_idea ON idea_versions(idea_id);
CREATE INDEX idx_idea_team_assignments_idea ON idea_team_assignments(idea_id);
CREATE INDEX idx_idea_team_assignments_team ON idea_team_assignments(team_id);
CREATE INDEX idx_team_invitations_team ON team_invitations(team_id);
CREATE INDEX idx_team_invitations_invitee ON team_invitations(invitee_id);
CREATE INDEX idx_team_invitations_status ON team_invitations(status);
CREATE INDEX idx_notifications_user ON notifications(user_id);
CREATE INDEX idx_notifications_is_read ON notifications(is_read);
CREATE INDEX idx_notifications_created ON notifications(created_at);
CREATE INDEX idx_flowcharts_owner ON flowcharts(owner_id);
CREATE INDEX idx_flowcharts_team ON flowcharts(team_id);
CREATE INDEX idx_flowcharts_folder ON flowcharts(folder_id);
CREATE INDEX idx_flowcharts_status ON flowcharts(status);
CREATE INDEX idx_flowcharts_created ON flowcharts(created_at);
CREATE INDEX idx_flowcharts_pinned ON flowcharts(is_pinned);

-- Trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_mfa_updated_at BEFORE UPDATE ON user_mfa
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_api_keys_updated_at BEFORE UPDATE ON user_api_keys
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_messages_updated_at BEFORE UPDATE ON messages
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_teams_updated_at BEFORE UPDATE ON teams
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_folders_updated_at BEFORE UPDATE ON drive_folders
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_files_updated_at BEFORE UPDATE ON drive_files
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_notes_updated_at BEFORE UPDATE ON notes
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_ideas_updated_at BEFORE UPDATE ON ideas
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_generated_images_updated_at BEFORE UPDATE ON generated_images
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_backup_schedules_updated_at BEFORE UPDATE ON backup_schedules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_flowcharts_updated_at BEFORE UPDATE ON flowcharts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
"""

def hash_password(password: str) -> str:
    """Hash password using Argon2id"""
    try:
        ph = PasswordHasher(
            time_cost=2,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            salt_len=16
        )
        return ph.hash(password)
    except HashingError as e:
        raise ValueError(f"Password hashing failed: {e}")

def create_tables(cursor):
    """Create all database tables"""
    print("Creating database tables...")
    cursor.execute(SQL_CREATE_TABLES)
    print("✓ Tables created successfully")

def create_admin_user(cursor, email: str, username: str, password: str, 
                     first_name: str = None, last_name: str = None):
    """Create initial admin user"""
    print("\nCreating admin user...")
    
    try:
        # Import encryption utilities
        from utils.encryption import generate_user_encryption_key, encrypt_user_key
        
        password_hash = hash_password(password)
        
        # Generate and encrypt user encryption key
        user_encryption_key = generate_user_encryption_key()
        encrypted_user_key = encrypt_user_key(user_encryption_key)
        
        query = """
            INSERT INTO users (
                email, username, password_hash, first_name, last_name,
                encryption_key, is_admin, is_active, account_status, email_verified
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, email, username, is_admin
        """

        cursor.execute(query, (
            email, username, password_hash, first_name, last_name, encrypted_user_key,
            True, True, 'active', True
        ))

        user = cursor.fetchone()
        user_id, user_email, user_username, is_admin = user
        
        # Log the admin creation
        log_query = """
            INSERT INTO audit_logs (user_id, action, status, details)
            VALUES (%s, 'admin_user_created', 'success', '{"method": "initial_setup"}'::jsonb)
        """
        cursor.execute(log_query, (user_id,))
        
        print(f"✓ Admin user created successfully")
        print(f"  ID: {user_id}")
        print(f"  Email: {user_email}")
        print(f"  Username: {user_username}")
        print(f"  Admin Flag: {is_admin}")
        
        return user_id
        
    except psycopg2.IntegrityError as e:
        if 'email' in str(e):
            raise ValueError(f"Email '{email}' already exists")
        elif 'username' in str(e):
            raise ValueError(f"Username '{username}' already exists")
        else:
            raise ValueError(f"Database integrity error: {e}")

def generate_secure_password(length=16):
    """
    Generate a secure password that won't be flagged by input validation.
    Avoids characters that might trigger SQL injection, XSS, or command injection filters.

    Uses:
    - Uppercase letters (A-Z)
    - Lowercase letters (a-z)
    - Numbers (0-9)
    - Safe special characters: !@%^*()_+-=[]{}.

    Avoids problematic characters:
    - Quotes (', ", `) - SQL injection
    - Semicolons (;) - SQL injection
    - Pipes (|), ampersands (&), dollar signs ($) - Command injection
    - Angle brackets (<, >) - XSS
    - Backslashes (\), slashes (/) - Path traversal
    - Hash (#) - Can cause URL encoding or parser issues
    """
    import secrets
    import string

    # Safe character sets
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    safe_special = '!@%^*()_+-=[]{}.'

    # Combine all safe characters
    all_chars = uppercase + lowercase + digits + safe_special

    # Generate password with guaranteed character diversity
    password = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(safe_special),
    ]

    # Fill the rest randomly
    password += [secrets.choice(all_chars) for _ in range(length - 4)]

    # Shuffle to avoid predictable patterns
    secrets.SystemRandom().shuffle(password)

    return ''.join(password)

def get_admin_details():
    """Prompt user for admin details"""
    print("\n" + "="*50)
    print("ADMIN USER SETUP")
    print("="*50)

    email = input("\nAdmin Email: ").strip()
    if not email or '@' not in email:
        print("Error: Invalid email address")
        sys.exit(1)

    username = input("Admin Username: ").strip()
    if not username or len(username) < 3:
        print("Error: Username must be at least 3 characters")
        sys.exit(1)

    # Ask if user wants to generate a secure password or enter their own
    print("\nPassword Setup:")
    print("  1. Auto-generate secure password (recommended)")
    print("  2. Enter custom password")
    choice = input("Choose option (1 or 2): ").strip()

    if choice == '1':
        # Auto-generate a secure password
        password = generate_secure_password(20)
        print("\n" + "="*50)
        print("GENERATED SECURE PASSWORD")
        print("="*50)
        print(f"\nPassword: {password}")
        print("\n⚠️  IMPORTANT: Save this password securely!")
        print("This password will only be shown once.\n")
        print("="*50)

        input("\nPress Enter when you have saved the password...")
    else:
        # Manual password entry
        while True:
            password = getpass("Admin Password: ")
            if len(password) < 8:
                print("Error: Password must be at least 8 characters")
                continue

            password_confirm = getpass("Confirm Password: ")
            if password != password_confirm:
                print("Error: Passwords do not match")
                continue
            break

    first_name = input("First Name (optional): ").strip() or None
    last_name = input("Last Name (optional): ").strip() or None

    return {
        'email': email,
        'username': username,
        'password': password,
        'first_name': first_name,
        'last_name': last_name
    }

def test_connection():
    """Test database connection"""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.close()
        return True
    except psycopg2.OperationalError as e:
        print(f"\n❌ Database connection failed:")
        print(f"   {e}")
        print(f"\nPlease check your database configuration:")
        print(f"   Host: {DB_CONFIG['host']}")
        print(f"   Port: {DB_CONFIG['port']}")
        print(f"   Database: {DB_CONFIG['dbname']}")
        print(f"   User: {DB_CONFIG['user']}")
        return False

def main():
    """Main setup function"""
    print("\n" + "="*50)
    print("DATABASE SETUP SCRIPT")
    print("="*50)
    print(f"\nDatabase: {DB_CONFIG['dbname']}")
    print(f"Host: {DB_CONFIG['host']}:{DB_CONFIG['port']}")
    print(f"User: {DB_CONFIG['user']}")
    
    # Test connection
    if not test_connection():
        sys.exit(1)
    
    print("\n✓ Database connection successful")
    
    # Confirm setup
    response = input("\n⚠️  This will DROP existing tables. Continue? (yes/no): ").strip().lower()
    if response not in ['yes', 'y']:
        print("Setup cancelled")
        sys.exit(0)
    
    # Get admin details
    admin_details = get_admin_details()
    
    # Connect and create tables
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Create tables
        create_tables(cursor)
        
        # Create admin user
        create_admin_user(
            cursor,
            email=admin_details['email'],
            username=admin_details['username'],
            password=admin_details['password'],
            first_name=admin_details['first_name'],
            last_name=admin_details['last_name']
        )
        
        # Commit changes
        conn.commit()
        
        print("\n" + "="*50)
        print("✓ SETUP COMPLETED SUCCESSFULLY")
        print("="*50)
        print("\nYou can now use the admin credentials to log in.")
        
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"\n❌ Setup failed: {e}")
        sys.exit(1)
        
    finally:
        if conn:
            cursor.close()
            conn.close()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user")
        sys.exit(0)