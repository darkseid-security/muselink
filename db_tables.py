from datetime import datetime
from enum import Enum
import secrets
from typing import Optional
from dataclasses import dataclass
from argon2 import PasswordHasher
from argon2.exceptions import HashingError

# Initialize Argon2 hasher
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16
)

# Database Models using dataclasses for clarity

class MFAMethod(Enum):
    """Enum for MFA methods"""
    TOTP = 'totp'  # Time-based One-Time Password (Google Authenticator)
    EMAIL = 'email'

class AccountStatus(Enum):
    """Enum for account status"""
    ACTIVE = 'active'
    SUSPENDED = 'suspended'
    PENDING_VERIFICATION = 'pending_verification'
    DELETED = 'deleted'

@dataclass
class User:
    """User account table"""
    id: Optional[int] = None
    email: str = None
    username: str = None
    password_hash: str = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    encryption_key: str = None
    is_admin: bool = False
    is_active: bool = True
    account_status: str = AccountStatus.PENDING_VERIFICATION.value
    email_verified: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None

@dataclass
class UserMFA:
    """User MFA configuration with double-encrypted TOTP secrets"""
    id: Optional[int] = None
    user_id: int = None

    # MFA Status
    mfa_enabled: bool = False
    mfa_verified: bool = False

    # Double-Encrypted TOTP Secret (Layer 1 + Layer 2)
    totp_secret_encrypted: Optional[str] = None  # Base64-encoded Layer 1 ciphertext
    totp_key_encrypted: Optional[str] = None     # Base64-encoded Layer 2 ciphertext (encrypted random key)
    totp_iv1: Optional[str] = None               # Base64-encoded IV for Layer 1
    totp_tag1: Optional[str] = None              # Base64-encoded authentication tag for Layer 1
    totp_iv2: Optional[str] = None               # Base64-encoded IV for Layer 2
    totp_tag2: Optional[str] = None              # Base64-encoded authentication tag for Layer 2

    # Backup Codes (Argon2id hashed)
    backup_codes: Optional[list] = None          # Array of hashed backup codes
    backup_codes_used: int = 0                   # Track how many used

    # Security Tracking
    last_used_at: Optional[datetime] = None      # Last successful MFA verification
    last_code_used: Optional[str] = None         # Hash of last TOTP code (prevent replay)

    # Timestamps
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

@dataclass
class MFAAuditLog:
    """MFA audit trail"""
    id: Optional[int] = None
    user_id: int = None
    action: str = None  # 'mfa_enabled', 'mfa_disabled', 'totp_success', 'totp_failed', 'backup_code_used'
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    success: bool = True
    failure_reason: Optional[str] = None
    created_at: Optional[datetime] = None

@dataclass
class UserSession:
    """Active user sessions table"""
    id: Optional[int] = None
    user_id: int = None
    session_token: str = None
    refresh_token: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    is_active: bool = True

@dataclass
class PasswordResetToken:
    """Password reset tokens table"""
    id: Optional[int] = None
    user_id: int = None
    token_hash: str = None
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    used_at: Optional[datetime] = None
    ip_address: Optional[str] = None

@dataclass
class EmailVerificationToken:
    """Email verification tokens table"""
    id: Optional[int] = None
    user_id: int = None
    token_hash: str = None
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    verified_at: Optional[datetime] = None

@dataclass
class AuditLog:
    """Audit log for security events"""
    id: Optional[int] = None
    user_id: Optional[int] = None
    action: str = None  # 'login', 'logout', 'password_change', 'mfa_enabled', etc.
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    status: str = None  # 'success', 'failed'
    details: Optional[str] = None  # JSON for additional info
    created_at: Optional[datetime] = None

@dataclass
class Message:
    """Messages between users (encrypted)"""
    id: Optional[int] = None
    sender_id: int = None
    receiver_id: int = None
    subject: Optional[str] = None
    content_sender: str = None  # Encrypted with sender's key
    content_receiver: str = None  # Encrypted with receiver's key
    is_read: bool = False
    read_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    deleted_by_sender: bool = False
    deleted_by_receiver: bool = False

@dataclass
class Team:
    """Teams for collaboration"""
    id: Optional[int] = None
    name: str = None
    description: Optional[str] = None
    owner_id: int = None
    team_key_encrypted: str = None  # Team encryption key, encrypted with owner's key
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    is_active: bool = True

@dataclass
class TeamMember:
    """Team membership and access control"""
    id: Optional[int] = None
    team_id: int = None
    user_id: int = None
    role: str = None  # 'owner', 'admin', 'member', 'viewer'
    team_key_encrypted: str = None  # Team key encrypted with user's key
    joined_at: Optional[datetime] = None
    added_by: Optional[int] = None
    is_active: bool = True

@dataclass
class DriveFolder:
    """Folders in encrypted drive"""
    id: Optional[int] = None
    name_encrypted: str = None  # Encrypted folder name
    owner_id: int = None
    team_id: Optional[int] = None  # NULL for personal, ID for team folders
    parent_folder_id: Optional[int] = None
    encryption_iv: str = None  # AES-GCM IV for folder metadata
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    is_deleted: bool = False

@dataclass
class DriveFile:
    """Files in encrypted drive"""
    id: Optional[int] = None
    filename_encrypted: str = None  # Encrypted filename
    file_path: str = None  # Path on disk (UUID-based)
    file_size: int = None  # Size in bytes
    mime_type_encrypted: str = None  # Encrypted MIME type
    owner_id: int = None
    team_id: Optional[int] = None
    folder_id: Optional[int] = None
    encryption_iv: str = None  # AES-GCM IV
    encryption_tag: str = None  # AES-GCM authentication tag
    checksum: str = None  # Argon2id hash of encrypted content
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    is_deleted: bool = False
    metadata_stripped: bool = True

@dataclass
class Note:
    """Encrypted notes"""
    id: Optional[int] = None
    title_encrypted: str = None
    content_encrypted: str = None
    owner_id: int = None
    team_id: Optional[int] = None
    folder_id: Optional[int] = None
    encryption_iv: str = None
    encryption_tag: str = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    is_deleted: bool = False
    is_pinned: bool = False

@dataclass
class Idea:
    """Collaborative ideas/documents"""
    id: Optional[int] = None
    title_encrypted: str = None
    description_encrypted: str = None
    content_encrypted: str = None
    owner_id: int = None
    team_id: Optional[int] = None
    status: str = None  # 'draft', 'in_progress', 'review', 'completed', 'archived'
    encryption_iv: str = None
    encryption_tag: str = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    is_deleted: bool = False

@dataclass
class IdeaContributor:
    """Contributors to ideas"""
    id: Optional[int] = None
    idea_id: int = None
    user_id: int = None
    role: str = None  # 'editor', 'commenter', 'viewer'
    added_at: Optional[datetime] = None
    added_by: int = None

@dataclass
class IdeaVersion:
    """Version history for ideas"""
    id: Optional[int] = None
    idea_id: int = None
    content_encrypted: str = None
    encryption_iv: str = None
    encryption_tag: str = None
    version_number: int = None
    created_by: int = None
    created_at: Optional[datetime] = None
    change_description_encrypted: Optional[str] = None

@dataclass
class IdeaTeamAssignment:
    """Team assignments for ideas"""
    id: Optional[int] = None
    idea_id: int = None
    team_id: int = None
    assigned_by: int = None
    assigned_at: Optional[datetime] = None

@dataclass
class Flowchart:
    """Flowcharts for product/workflow design"""
    id: Optional[int] = None
    title_encrypted: str = None
    description_encrypted: Optional[str] = None
    flowchart_data_encrypted: str = None  # Mermaid code or JSON structure
    flowchart_type: str = None  # 'mermaid', 'json', 'custom'
    owner_id: int = None
    team_id: Optional[int] = None
    folder_id: Optional[int] = None
    template_name: Optional[str] = None  # Reference to predefined templates
    status: str = None  # 'draft', 'in_progress', 'review', 'completed', 'archived'
    encryption_iv: str = None
    encryption_tag: str = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    is_deleted: bool = False
    is_pinned: bool = False
    thumbnail_encrypted: Optional[str] = None  # Base64 PNG thumbnail
    node_notes: Optional[str] = '{}'  # JSON string of interactive node notes

@dataclass
class TeamInvitation:
    """Team invitation requests"""
    id: Optional[int] = None
    team_id: int = None
    inviter_id: int = None
    invitee_id: int = None
    status: str = 'pending'  # 'pending', 'accepted', 'rejected', 'cancelled'
    message: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None

@dataclass
class Notification:
    """User notifications"""
    id: Optional[int] = None
    user_id: int = None
    type: str = None  # 'team_invitation', 'team_invitation_accepted', 'team_member_removed', etc.
    title: str = None
    message: str = None
    is_read: bool = False
    priority: str = 'normal'  # 'low', 'normal', 'high', 'urgent'
    related_type: Optional[str] = None  # 'team_invitation', 'team', 'file', etc.
    related_id: Optional[int] = None
    action_url: Optional[str] = None
    created_at: Optional[datetime] = None
    read_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None

# SQL Table Creation Scripts

SQL_CREATE_TABLES = """
-- Users table
CREATE TABLE IF NOT EXISTS users (
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
CREATE TABLE IF NOT EXISTS user_mfa (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mfa_method VARCHAR(20) NOT NULL,
    is_enabled BOOLEAN DEFAULT FALSE,
    secret_key TEXT,
    backup_codes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP,
    mfa_code_hash TEXT,
    mfa_code_expires_at TIMESTAMP,
    CONSTRAINT chk_mfa_method CHECK (mfa_method IN ('totp', 'email')),
    UNIQUE(user_id, mfa_method)
);

-- User sessions table
CREATE TABLE IF NOT EXISTS user_sessions (
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
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    ip_address INET
);

-- Email verification tokens table
CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    verified_at TIMESTAMP
);

-- Audit log table
CREATE TABLE IF NOT EXISTS audit_logs (
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
CREATE TABLE IF NOT EXISTS messages (
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
CREATE TABLE IF NOT EXISTS teams (
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
CREATE TABLE IF NOT EXISTS team_members (
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
CREATE TABLE IF NOT EXISTS drive_folders (
    id SERIAL PRIMARY KEY,
    name_encrypted TEXT NOT NULL,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    parent_folder_id INTEGER REFERENCES drive_folders(id) ON DELETE CASCADE,
    encryption_iv VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN DEFAULT FALSE,
    CONSTRAINT chk_folder_ownership CHECK (
        (team_id IS NULL AND owner_id IS NOT NULL) OR
        (team_id IS NOT NULL)
    )
);

-- Drive files table
CREATE TABLE IF NOT EXISTS drive_files (
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
CREATE TABLE IF NOT EXISTS notes (
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
CREATE TABLE IF NOT EXISTS ideas (
    id SERIAL PRIMARY KEY,
    title_encrypted TEXT NOT NULL,
    description_encrypted TEXT,
    content_encrypted TEXT NOT NULL,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    status VARCHAR(20) DEFAULT 'draft',
    encryption_iv VARCHAR(64) NOT NULL,
    encryption_tag VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN DEFAULT FALSE,
    CONSTRAINT chk_idea_status CHECK (status IN ('draft', 'in_progress', 'review', 'completed', 'archived'))
);

-- Idea contributors table
CREATE TABLE IF NOT EXISTS idea_contributors (
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
CREATE TABLE IF NOT EXISTS idea_versions (
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
CREATE TABLE IF NOT EXISTS idea_team_assignments (
    id SERIAL PRIMARY KEY,
    idea_id INTEGER NOT NULL REFERENCES ideas(id) ON DELETE CASCADE,
    team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    assigned_by INTEGER NOT NULL REFERENCES users(id),
    assigned_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(idea_id, team_id)
);

-- Team invitations table
CREATE TABLE IF NOT EXISTS team_invitations (
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
CREATE TABLE IF NOT EXISTS notifications (
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

-- Flowcharts table
CREATE TABLE IF NOT EXISTS flowcharts (
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
    encryption_iv VARCHAR(64) NOT NULL,
    encryption_tag VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN DEFAULT FALSE,
    is_pinned BOOLEAN DEFAULT FALSE,
    thumbnail_encrypted TEXT,
    node_notes TEXT DEFAULT '{}',
    CONSTRAINT chk_flowchart_type CHECK (flowchart_type IN ('mermaid', 'json', 'custom')),
    CONSTRAINT chk_flowchart_status CHECK (status IN ('draft', 'in_progress', 'review', 'completed', 'archived'))
);

-- Security incidents table (for malicious input tracking)
CREATE TABLE IF NOT EXISTS security_incidents (
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
CREATE TABLE IF NOT EXISTS drive_backups (
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
CREATE TABLE IF NOT EXISTS backup_schedules (
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
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_is_admin ON users(is_admin);
CREATE INDEX IF NOT EXISTS idx_user_mfa_user_id ON user_mfa(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_password_reset_user ON password_reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_email_verify_user ON email_verification_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id);
CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at);
CREATE INDEX IF NOT EXISTS idx_messages_is_read ON messages(is_read);
CREATE INDEX IF NOT EXISTS idx_security_incidents_user ON security_incidents(user_id);
CREATE INDEX IF NOT EXISTS idx_security_incidents_type ON security_incidents(incident_type);
CREATE INDEX IF NOT EXISTS idx_security_incidents_severity ON security_incidents(severity);
CREATE INDEX IF NOT EXISTS idx_security_incidents_created ON security_incidents(created_at);

-- Backup indexes
CREATE INDEX IF NOT EXISTS idx_backups_owner ON drive_backups(owner_id);
CREATE INDEX IF NOT EXISTS idx_backups_team ON drive_backups(team_id);
CREATE INDEX IF NOT EXISTS idx_backups_created ON drive_backups(created_at);
CREATE INDEX IF NOT EXISTS idx_backups_status ON drive_backups(status);
CREATE INDEX IF NOT EXISTS idx_backup_schedules_user ON backup_schedules(user_id);
CREATE INDEX IF NOT EXISTS idx_backup_schedules_team ON backup_schedules(team_id);
CREATE INDEX IF NOT EXISTS idx_backup_schedules_next ON backup_schedules(next_backup_at);

-- Drive indexes
CREATE INDEX IF NOT EXISTS idx_teams_owner ON teams(owner_id);
CREATE INDEX IF NOT EXISTS idx_team_members_team ON team_members(team_id);
CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(user_id);
CREATE INDEX IF NOT EXISTS idx_folders_owner ON drive_folders(owner_id);
CREATE INDEX IF NOT EXISTS idx_folders_team ON drive_folders(team_id);
CREATE INDEX IF NOT EXISTS idx_folders_parent ON drive_folders(parent_folder_id);
CREATE INDEX IF NOT EXISTS idx_files_owner ON drive_files(owner_id);
CREATE INDEX IF NOT EXISTS idx_files_team ON drive_files(team_id);
CREATE INDEX IF NOT EXISTS idx_files_folder ON drive_files(folder_id);
CREATE INDEX IF NOT EXISTS idx_files_created ON drive_files(created_at);
CREATE INDEX IF NOT EXISTS idx_notes_owner ON notes(owner_id);
CREATE INDEX IF NOT EXISTS idx_notes_team ON notes(team_id);
CREATE INDEX IF NOT EXISTS idx_notes_folder ON notes(folder_id);
CREATE INDEX IF NOT EXISTS idx_notes_pinned ON notes(is_pinned);
CREATE INDEX IF NOT EXISTS idx_ideas_owner ON ideas(owner_id);
CREATE INDEX IF NOT EXISTS idx_ideas_team ON ideas(team_id);
CREATE INDEX IF NOT EXISTS idx_ideas_status ON ideas(status);
CREATE INDEX IF NOT EXISTS idx_idea_contributors_idea ON idea_contributors(idea_id);
CREATE INDEX IF NOT EXISTS idx_idea_contributors_user ON idea_contributors(user_id);
CREATE INDEX IF NOT EXISTS idx_idea_versions_idea ON idea_versions(idea_id);
CREATE INDEX IF NOT EXISTS idx_idea_team_assignments_idea ON idea_team_assignments(idea_id);
CREATE INDEX IF NOT EXISTS idx_idea_team_assignments_team ON idea_team_assignments(team_id);
CREATE INDEX IF NOT EXISTS idx_team_invitations_team ON team_invitations(team_id);
CREATE INDEX IF NOT EXISTS idx_team_invitations_invitee ON team_invitations(invitee_id);
CREATE INDEX IF NOT EXISTS idx_team_invitations_status ON team_invitations(status);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_is_read ON notifications(is_read);
CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at);
CREATE INDEX IF NOT EXISTS idx_flowcharts_owner ON flowcharts(owner_id);
CREATE INDEX IF NOT EXISTS idx_flowcharts_team ON flowcharts(team_id);
CREATE INDEX IF NOT EXISTS idx_flowcharts_folder ON flowcharts(folder_id);
CREATE INDEX IF NOT EXISTS idx_flowcharts_status ON flowcharts(status);
CREATE INDEX IF NOT EXISTS idx_flowcharts_created ON flowcharts(created_at);
CREATE INDEX IF NOT EXISTS idx_flowcharts_pinned ON flowcharts(is_pinned);

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

CREATE TRIGGER update_flowcharts_updated_at BEFORE UPDATE ON flowcharts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- RBAC (Role-Based Access Control) Tables
-- ============================================================================

-- System roles table
CREATE TABLE IF NOT EXISTS system_roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    hierarchy_level INTEGER NOT NULL DEFAULT 1,
    is_system_role BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_role_name CHECK (name IN (
        'super_admin', 'admin', 'content_manager',
        'team_lead', 'creative_user', 'viewer'
    )),
    CONSTRAINT chk_hierarchy_level CHECK (hierarchy_level BETWEEN 1 AND 6)
);

-- System permissions table
CREATE TABLE IF NOT EXISTS system_permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    category VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Role-Permission mapping
CREATE TABLE IF NOT EXISTS role_permissions (
    id SERIAL PRIMARY KEY,
    role_id INTEGER NOT NULL REFERENCES system_roles(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES system_permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(role_id, permission_id)
);

-- User-Role mapping (users can have multiple roles)
CREATE TABLE IF NOT EXISTS user_system_roles (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES system_roles(id) ON DELETE CASCADE,
    assigned_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    UNIQUE(user_id, role_id)
);

-- RBAC Indexes
CREATE INDEX IF NOT EXISTS idx_user_system_roles_user ON user_system_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_system_roles_role ON user_system_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission ON role_permissions(permission_id);

-- Insert default system roles
INSERT INTO system_roles (name, display_name, description, hierarchy_level, is_system_role) VALUES
    ('super_admin', 'Super Administrator', 'Full system access and control', 6, TRUE),
    ('admin', 'Administrator', 'User and system management', 5, TRUE),
    ('content_manager', 'Content Manager', 'Manage all creative content', 4, TRUE),
    ('team_lead', 'Team Lead', 'Manage team content and approvals', 3, TRUE),
    ('creative_user', 'Creative User', 'Create and manage own content', 2, TRUE),
    ('viewer', 'Viewer', 'Read-only access', 1, TRUE)
ON CONFLICT (name) DO NOTHING;

-- Insert default permissions
INSERT INTO system_permissions (name, display_name, description, category) VALUES
    -- System Administration
    ('manage_system_settings', 'Manage System Settings', 'Configure application settings', 'system'),
    ('view_system_logs', 'View System Logs', 'Access application logs', 'system'),
    ('manage_integrations', 'Manage Integrations', 'Configure third-party integrations', 'system'),

    -- User Management
    ('create_user', 'Create User', 'Create new user accounts', 'user_management'),
    ('update_user', 'Update User', 'Modify user account details', 'user_management'),
    ('delete_user', 'Delete User', 'Remove user accounts', 'user_management'),
    ('view_all_users', 'View All Users', 'Access all user information', 'user_management'),
    ('assign_roles', 'Assign Roles', 'Grant roles to users', 'user_management'),

    -- Content Management - Own
    ('create_content', 'Create Content', 'Create new content', 'content_own'),
    ('update_own_content', 'Update Own Content', 'Modify own content', 'content_own'),
    ('delete_own_content', 'Delete Own Content', 'Remove own content', 'content_own'),
    ('view_own_content', 'View Own Content', 'Access own content', 'content_own'),

    -- Content Management - Team
    ('view_team_content', 'View Team Content', 'Access team content', 'content_team'),
    ('update_team_content', 'Update Team Content', 'Modify team content', 'content_team'),
    ('delete_team_content', 'Delete Team Content', 'Remove team content', 'content_team'),
    ('approve_team_content', 'Approve Team Content', 'Approve team submissions', 'content_team'),

    -- Content Management - All
    ('view_all_content', 'View All Content', 'Access all content', 'content_all'),
    ('update_all_content', 'Update All Content', 'Modify any content', 'content_all'),
    ('delete_all_content', 'Delete All Content', 'Remove any content', 'content_all'),
    ('approve_all_content', 'Approve All Content', 'Approve any submissions', 'content_all'),

    -- Encrypted Drive
    ('manage_own_files', 'Manage Own Files', 'Upload/delete own encrypted files', 'drive'),
    ('manage_team_files', 'Manage Team Files', 'Manage team encrypted files', 'drive'),
    ('manage_all_files', 'Manage All Files', 'Manage all encrypted files', 'drive'),
    ('create_backup', 'Create Backup', 'Create encrypted backups', 'drive'),
    ('restore_backup', 'Restore Backup', 'Restore from backups', 'drive'),

    -- Analytics & Reporting
    ('view_own_analytics', 'View Own Analytics', 'View personal analytics', 'analytics'),
    ('view_team_analytics', 'View Team Analytics', 'View team analytics', 'analytics'),
    ('view_all_analytics', 'View All Analytics', 'View system-wide analytics', 'analytics'),
    ('export_reports', 'Export Reports', 'Export data and reports', 'analytics'),

    -- Audit & Security
    ('view_audit_logs', 'View Audit Logs', 'Access security audit logs', 'security'),
    ('manage_security_settings', 'Manage Security Settings', 'Configure security policies', 'security'),
    ('view_security_incidents', 'View Security Incidents', 'Review security incidents', 'security')
ON CONFLICT (name) DO NOTHING;

-- Map permissions to roles
-- Super Admin - All permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT sr.id, sp.id
FROM system_roles sr
CROSS JOIN system_permissions sp
WHERE sr.name = 'super_admin'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Admin
INSERT INTO role_permissions (role_id, permission_id)
SELECT sr.id, sp.id
FROM system_roles sr, system_permissions sp
WHERE sr.name = 'admin'
AND sp.name IN (
    'view_system_logs', 'create_user', 'update_user', 'delete_user',
    'view_all_users', 'assign_roles', 'view_all_content', 'update_all_content',
    'delete_all_content', 'approve_all_content', 'manage_all_files',
    'view_all_analytics', 'export_reports', 'view_audit_logs'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Content Manager
INSERT INTO role_permissions (role_id, permission_id)
SELECT sr.id, sp.id
FROM system_roles sr, system_permissions sp
WHERE sr.name = 'content_manager'
AND sp.name IN (
    'create_content', 'update_own_content', 'delete_own_content', 'view_own_content',
    'view_all_content', 'update_all_content', 'delete_all_content', 'approve_all_content',
    'manage_own_files', 'manage_team_files', 'create_backup',
    'view_all_analytics', 'export_reports'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Team Lead
INSERT INTO role_permissions (role_id, permission_id)
SELECT sr.id, sp.id
FROM system_roles sr, system_permissions sp
WHERE sr.name = 'team_lead'
AND sp.name IN (
    'create_content', 'update_own_content', 'delete_own_content', 'view_own_content',
    'view_team_content', 'update_team_content', 'delete_team_content', 'approve_team_content',
    'manage_own_files', 'manage_team_files', 'create_backup',
    'view_own_analytics', 'view_team_analytics', 'export_reports'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Creative User
INSERT INTO role_permissions (role_id, permission_id)
SELECT sr.id, sp.id
FROM system_roles sr, system_permissions sp
WHERE sr.name = 'creative_user'
AND sp.name IN (
    'create_content', 'update_own_content', 'delete_own_content', 'view_own_content',
    'manage_own_files', 'create_backup', 'view_own_analytics'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Viewer
INSERT INTO role_permissions (role_id, permission_id)
SELECT sr.id, sp.id
FROM system_roles sr, system_permissions sp
WHERE sr.name = 'viewer'
AND sp.name IN (
    'view_own_content', 'view_team_content', 'view_own_analytics'
)
ON CONFLICT (role_id, permission_id) DO NOTHING;
"""

# Utility functions for security

def hash_password(password: str) -> str:
    """
    Hash password using Argon2id algorithm.
    Argon2id is the recommended hashing algorithm as it combines:
    - Memory hardness (resistant to GPU attacks)
    - Data-dependent memory access (resistant to side-channel attacks)
    
    Install: pip install argon2-cffi
    """
    from argon2 import PasswordHasher
    from argon2.exceptions import HashingError
    
    try:
        ph = PasswordHasher(
            time_cost=2,        # Number of iterations
            memory_cost=65536,  # Memory usage in KiB (64 MB)
            parallelism=4,      # Number of parallel threads
            hash_len=32,        # Length of the hash in bytes
            salt_len=16         # Length of random salt in bytes
        )
        return ph.hash(password)
    except HashingError as e:
        raise ValueError(f"Password hashing failed: {e}")

def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify password against Argon2id hash.
    Also handles automatic rehashing if parameters have changed.
    """
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, InvalidHash, VerificationError
    
    ph = PasswordHasher(
        time_cost=2,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        salt_len=16
    )
    
    try:
        # Verify the password
        ph.verify(password_hash, password)
        
        # Check if rehash is needed (parameters changed)
        if ph.check_needs_rehash(password_hash):
            # Return True but signal that rehash is needed
            # In production, update the hash in the database
            return True
        
        return True
    except (VerifyMismatchError, InvalidHash, VerificationError):
        return False

def generate_token() -> str:
    """Generate a secure random token"""
    return secrets.token_urlsafe(32)

def hash_token(token: str) -> str:
    """Hash token for storage using Argon2id"""
    try:
        return ph.hash(token)
    except HashingError as e:
        raise ValueError(f"Token hashing failed: {e}")

# Example usage functions

def create_user_example(cursor, email: str, username: str, password: str, is_admin: bool = False):
    """Example function to create a user"""
    password_hash = hash_password(password)
    
    query = """
        INSERT INTO users (email, username, password_hash, is_admin)
        VALUES (%s, %s, %s, %s)
        RETURNING id
    """
    cursor.execute(query, (email, username, password_hash, is_admin))
    user_id = cursor.fetchone()[0]
    return user_id

def enable_mfa_example(cursor, user_id: int, mfa_method: str, secret_key: str = None):
    """Example function to enable MFA for a user"""
    query = """
        INSERT INTO user_mfa (user_id, mfa_method, is_enabled, secret_key)
        VALUES (%s, %s, TRUE, %s)
        ON CONFLICT (user_id, mfa_method) 
        DO UPDATE SET is_enabled = TRUE, secret_key = EXCLUDED.secret_key
        RETURNING id
    """
    cursor.execute(query, (user_id, mfa_method, secret_key))
    return cursor.fetchone()[0]

def create_session_example(cursor, user_id: int, ip_address: str, user_agent: str):
    """Example function to create a user session"""
    session_token = generate_token()
    refresh_token = generate_token()
    
    query = """
        INSERT INTO user_sessions (user_id, session_token, refresh_token, ip_address, user_agent, expires_at)
        VALUES (%s, %s, %s, %s, %s, NOW() + INTERVAL '7 days')
        RETURNING id, session_token, refresh_token
    """
    cursor.execute(query, (user_id, session_token, refresh_token, ip_address, user_agent))
    return cursor.fetchone()

def log_audit_event(cursor, user_id: int, action: str, status: str, ip_address: str = None, details: dict = None):
    """Example function to log audit events"""
    import json
    query = """
        INSERT INTO audit_logs (user_id, action, status, ip_address, details)
        VALUES (%s, %s, %s, %s, %s)
    """
    cursor.execute(query, (user_id, action, status, ip_address, json.dumps(details) if details else None))

# Message utility functions

def send_message(cursor, sender_id: int, receiver_id: int, content_sender: str, content_receiver: str, subject: str = None):
    """Send an encrypted message from one user to another"""
    query = """
        INSERT INTO messages (sender_id, receiver_id, subject, content_sender, content_receiver)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id, created_at
    """
    cursor.execute(query, (sender_id, receiver_id, subject, content_sender, content_receiver))
    return cursor.fetchone()

def get_user_messages(cursor, user_id: int, as_sender: bool = False, as_receiver: bool = True,
                      include_deleted: bool = False, unread_only: bool = False):
    """
    Get messages for a user

    Args:
        cursor: Database cursor
        user_id: ID of the user
        as_sender: Include messages sent by the user
        as_receiver: Include messages received by the user
        include_deleted: Include messages deleted by the user
        unread_only: Only return unread messages (only applies when as_receiver=True)
    """
    conditions = []
    params = []

    if as_receiver:
        conditions.append("(receiver_id = %s AND deleted_by_receiver = %s)")
        params.extend([user_id, include_deleted])
        if unread_only:
            conditions.append("is_read = FALSE")

    if as_sender:
        conditions.append("(sender_id = %s AND deleted_by_sender = %s)")
        params.extend([user_id, include_deleted])

    where_clause = " OR ".join(conditions) if conditions else "1=0"

    query = f"""
        SELECT m.id, m.sender_id, m.receiver_id, m.subject, m.content_sender, m.content_receiver,
               m.is_read, m.read_at, m.created_at, m.updated_at,
               s.username as sender_username, r.username as receiver_username
        FROM messages m
        JOIN users s ON m.sender_id = s.id
        JOIN users r ON m.receiver_id = r.id
        WHERE {where_clause}
        ORDER BY m.created_at DESC
    """

    cursor.execute(query, params)
    return cursor.fetchall()

def mark_message_as_read(cursor, message_id: int, user_id: int):
    """Mark a message as read (only if user is the receiver)"""
    query = """
        UPDATE messages
        SET is_read = TRUE, read_at = NOW()
        WHERE id = %s AND receiver_id = %s AND is_read = FALSE
        RETURNING id
    """
    cursor.execute(query, (message_id, user_id))
    return cursor.fetchone() is not None

def delete_message(cursor, message_id: int, user_id: int):
    """
    Soft delete a message for a user
    If both users delete, the message remains in DB for audit
    """
    query = """
        UPDATE messages
        SET deleted_by_sender = CASE WHEN sender_id = %s THEN TRUE ELSE deleted_by_sender END,
            deleted_by_receiver = CASE WHEN receiver_id = %s THEN TRUE ELSE deleted_by_receiver END
        WHERE id = %s AND (sender_id = %s OR receiver_id = %s)
        RETURNING id
    """
    cursor.execute(query, (user_id, user_id, message_id, user_id, user_id))
    return cursor.fetchone() is not None

def get_unread_message_count(cursor, user_id: int):
    """Get count of unread messages for a user"""
    query = """
        SELECT COUNT(*)
        FROM messages
        WHERE receiver_id = %s
          AND is_read = FALSE
          AND deleted_by_receiver = FALSE
    """
    cursor.execute(query, (user_id,))
    return cursor.fetchone()[0]
