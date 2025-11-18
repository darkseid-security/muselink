"""
database/models.py
SQLAlchemy Core Table Definitions
Provides automatic SQL injection protection through query builder pattern

Security Features:
- Automatic parameterization (SQLAlchemy Core)
- Type validation at database layer
- Second-order SQL injection protection via text() with explicit binds
- No raw SQL string concatenation possible
"""

from sqlalchemy import (
    MetaData, Table, Column, Integer, String, Text, Boolean,
    DateTime, BigInteger, ForeignKey, CheckConstraint, UniqueConstraint,
    Index, TIMESTAMP, func, Enum as SQLEnum, JSON
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from enum import Enum
import datetime

# SQLAlchemy metadata object
metadata = MetaData()

# Enums
class AccountStatusEnum(str, Enum):
    ACTIVE = 'active'
    SUSPENDED = 'suspended'
    PENDING_VERIFICATION = 'pending_verification'
    DELETED = 'deleted'

class MFAMethodEnum(str, Enum):
    TOTP = 'totp'
    EMAIL = 'email'

class TeamRoleEnum(str, Enum):
    OWNER = 'owner'
    ADMIN = 'admin'
    MEMBER = 'member'
    VIEWER = 'viewer'

class IdeaStatusEnum(str, Enum):
    DRAFT = 'draft'
    IN_PROGRESS = 'in_progress'
    REVIEW = 'review'
    COMPLETED = 'completed'
    ARCHIVED = 'archived'

class BackupTypeEnum(str, Enum):
    FULL = 'full'
    INCREMENTAL = 'incremental'
    DIFFERENTIAL = 'differential'

class BackupStatusEnum(str, Enum):
    IN_PROGRESS = 'in_progress'
    COMPLETED = 'completed'
    FAILED = 'failed'
    EXPIRED = 'expired'

class FrequencyEnum(str, Enum):
    DAILY = 'daily'
    WEEKLY = 'weekly'
    MONTHLY = 'monthly'

# =============================================================================
# Core Tables
# =============================================================================

users = Table(
    'users', metadata,
    Column('id', Integer, primary_key=True),
    Column('email', String(255), unique=True, nullable=False, index=True),
    Column('username', String(100), unique=True, nullable=False, index=True),
    Column('password_hash', String(255), nullable=False),
    Column('first_name', String(100)),
    Column('last_name', String(100)),
    Column('encryption_key', Text, nullable=False),
    Column('google_id', String(255), unique=True, nullable=True, index=True),  # Google OAuth ID
    Column('is_admin', Boolean, default=False, index=True),
    Column('is_active', Boolean, default=True),
    Column('account_status', String(50), default='pending_verification'),
    Column('email_verified', Boolean, default=False),
    Column('created_at', DateTime, server_default=func.now()),
    Column('updated_at', DateTime, server_default=func.now(), onupdate=func.now()),
    Column('last_login', DateTime),
    Column('failed_login_attempts', Integer, default=0),
    Column('locked_until', DateTime),
    CheckConstraint(
        "account_status IN ('active', 'suspended', 'pending_verification', 'deleted')",
        name='chk_account_status'
    )
)

user_mfa = Table(
    'user_mfa', metadata,
    Column('id', Integer, primary_key=True),
    Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, unique=True, index=True),

    # MFA Status
    Column('mfa_enabled', Boolean, default=False, nullable=False, index=True),
    Column('mfa_verified', Boolean, default=False, nullable=False),

    # Double-Encrypted TOTP Secret (Layer 1 + Layer 2)
    Column('totp_secret_encrypted', Text),  # Base64-encoded Layer 1 ciphertext
    Column('totp_key_encrypted', Text),     # Base64-encoded Layer 2 ciphertext (encrypted random key)
    Column('totp_iv1', Text),               # Base64-encoded IV for Layer 1
    Column('totp_tag1', Text),              # Base64-encoded authentication tag for Layer 1
    Column('totp_iv2', Text),               # Base64-encoded IV for Layer 2
    Column('totp_tag2', Text),              # Base64-encoded authentication tag for Layer 2

    # Backup Codes (Argon2id hashed)
    Column('backup_codes', JSON),           # Array of hashed backup codes
    Column('backup_codes_used', Integer, default=0),  # Track how many used

    # Security Tracking
    Column('last_used_at', DateTime),       # Last successful MFA verification
    Column('last_code_used', String(64)),   # Hash of last TOTP code (prevent replay)

    # Timestamps
    Column('created_at', DateTime, server_default=func.now()),
    Column('updated_at', DateTime, server_default=func.now(), onupdate=func.now())
)

mfa_audit_log = Table(
    'mfa_audit_log', metadata,
    Column('id', Integer, primary_key=True),
    Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('action', String(50), nullable=False, index=True),
    Column('ip_address', INET),
    Column('user_agent', Text),
    Column('success', Boolean, default=True),
    Column('failure_reason', Text),
    Column('created_at', DateTime, server_default=func.now(), index=True),
    CheckConstraint(
        "action IN ('mfa_enabled', 'mfa_disabled', 'mfa_verified', 'totp_success', 'totp_failed', "
        "'backup_code_used', 'qr_code_generated', 'backup_codes_regenerated')",
        name='chk_mfa_action'
    )
)

user_sessions = Table(
    'user_sessions', metadata,
    Column('id', Integer, primary_key=True),
    Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('session_token', String(255), unique=True, nullable=False, index=True),
    Column('refresh_token', String(255), unique=True),
    Column('ip_address', INET),
    Column('user_agent', Text),
    Column('created_at', DateTime, server_default=func.now()),
    Column('expires_at', DateTime, nullable=False, index=True),
    Column('last_activity', DateTime, server_default=func.now()),
    Column('is_active', Boolean, default=True)
)

password_reset_tokens = Table(
    'password_reset_tokens', metadata,
    Column('id', Integer, primary_key=True),
    Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('token_hash', String(255), unique=True, nullable=False),
    Column('created_at', DateTime, server_default=func.now()),
    Column('expires_at', DateTime, nullable=False),
    Column('used_at', DateTime),
    Column('ip_address', INET)
)

email_verification_tokens = Table(
    'email_verification_tokens', metadata,
    Column('id', Integer, primary_key=True),
    Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('token_hash', String(255), unique=True, nullable=False),
    Column('created_at', DateTime, server_default=func.now()),
    Column('expires_at', DateTime, nullable=False),
    Column('verified_at', DateTime)
)

audit_logs = Table(
    'audit_logs', metadata,
    Column('id', Integer, primary_key=True),
    Column('user_id', Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True),
    Column('action', String(100), nullable=False),
    Column('ip_address', INET),
    Column('user_agent', Text),
    Column('status', String(20), nullable=False),
    Column('details', JSONB),
    Column('created_at', DateTime, server_default=func.now(), index=True),
    CheckConstraint("status IN ('success', 'failed')", name='chk_status')
)

security_incidents = Table(
    'security_incidents', metadata,
    Column('id', Integer, primary_key=True),
    Column('user_id', Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True),
    Column('incident_type', String(50), nullable=False, index=True),
    Column('severity', String(20), nullable=False, index=True),
    Column('ip_address', INET),
    Column('endpoint', String(255)),
    Column('input_sample', Text),
    Column('pattern_matched', Text),
    Column('details', JSONB),
    Column('created_at', DateTime, server_default=func.now(), index=True),
    CheckConstraint("severity IN ('low', 'medium', 'high', 'critical')", name='chk_severity')
)

# =============================================================================
# Messaging Tables
# =============================================================================

messages = Table(
    'messages', metadata,
    Column('id', Integer, primary_key=True),
    Column('sender_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('receiver_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('subject', String(255)),
    Column('content_sender', Text, nullable=False),
    Column('content_receiver', Text, nullable=False),
    Column('is_read', Boolean, default=False, index=True),
    Column('read_at', DateTime),
    Column('created_at', DateTime, server_default=func.now(), index=True),
    Column('updated_at', DateTime, server_default=func.now(), onupdate=func.now()),
    Column('deleted_by_sender', Boolean, default=False),
    Column('deleted_by_receiver', Boolean, default=False),
    CheckConstraint('sender_id != receiver_id', name='chk_different_users')
)

# =============================================================================
# Team Collaboration Tables
# =============================================================================

teams = Table(
    'teams', metadata,
    Column('id', Integer, primary_key=True),
    Column('name', String(255), nullable=False),
    Column('description', Text),
    Column('owner_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('team_key_encrypted', Text, nullable=False),
    Column('created_at', DateTime, server_default=func.now()),
    Column('updated_at', DateTime, server_default=func.now(), onupdate=func.now()),
    Column('is_active', Boolean, default=True)
)

team_members = Table(
    'team_members', metadata,
    Column('id', Integer, primary_key=True),
    Column('team_id', Integer, ForeignKey('teams.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('role', String(20), nullable=False),
    Column('team_key_encrypted', Text, nullable=False),
    Column('joined_at', DateTime, server_default=func.now()),
    Column('added_by', Integer, ForeignKey('users.id', ondelete='SET NULL')),
    Column('is_active', Boolean, default=True),
    CheckConstraint("role IN ('owner', 'admin', 'member', 'viewer')", name='chk_team_role'),
    UniqueConstraint('team_id', 'user_id', name='uq_team_user')
)

# =============================================================================
# Encrypted Drive Tables
# =============================================================================

drive_folders = Table(
    'drive_folders', metadata,
    Column('id', Integer, primary_key=True),
    Column('name_encrypted', Text, nullable=False),
    Column('owner_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('team_id', Integer, ForeignKey('teams.id', ondelete='CASCADE'), index=True),
    Column('parent_folder_id', Integer, ForeignKey('drive_folders.id', ondelete='CASCADE'), index=True),
    Column('encryption_iv', String(64), nullable=False),
    Column('created_at', DateTime, server_default=func.now()),
    Column('updated_at', DateTime, server_default=func.now(), onupdate=func.now()),
    Column('is_deleted', Boolean, default=False),
    CheckConstraint(
        "(team_id IS NULL AND owner_id IS NOT NULL) OR (team_id IS NOT NULL)",
        name='chk_folder_ownership'
    )
)

drive_files = Table(
    'drive_files', metadata,
    Column('id', Integer, primary_key=True),
    Column('filename_encrypted', Text, nullable=False),
    Column('file_path', String(500), unique=True, nullable=False),
    Column('file_size', BigInteger, nullable=False),
    Column('mime_type_encrypted', Text, nullable=False),
    Column('owner_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('team_id', Integer, ForeignKey('teams.id', ondelete='CASCADE'), index=True),
    Column('folder_id', Integer, ForeignKey('drive_folders.id', ondelete='SET NULL'), index=True),
    Column('encryption_iv', String(64), nullable=False),
    Column('encryption_tag', String(64), nullable=False),
    Column('checksum', Text, nullable=False),
    Column('created_at', DateTime, server_default=func.now(), index=True),
    Column('updated_at', DateTime, server_default=func.now(), onupdate=func.now()),
    Column('is_deleted', Boolean, default=False),
    Column('metadata_stripped', Boolean, default=True),
    CheckConstraint('file_size > 0 AND file_size <= 10485760', name='chk_file_size'),
    CheckConstraint(
        "(team_id IS NULL AND owner_id IS NOT NULL) OR (team_id IS NOT NULL)",
        name='chk_file_ownership'
    )
)

notes = Table(
    'notes', metadata,
    Column('id', Integer, primary_key=True),
    Column('title_encrypted', Text, nullable=False),
    Column('content_encrypted', Text, nullable=False),
    Column('owner_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('team_id', Integer, ForeignKey('teams.id', ondelete='CASCADE'), index=True),
    Column('folder_id', Integer, ForeignKey('drive_folders.id', ondelete='SET NULL'), index=True),
    Column('encryption_iv', String(64), nullable=False),
    Column('encryption_tag', String(64), nullable=False),
    Column('created_at', DateTime, server_default=func.now()),
    Column('updated_at', DateTime, server_default=func.now(), onupdate=func.now()),
    Column('is_deleted', Boolean, default=False),
    Column('is_pinned', Boolean, default=False, index=True)
)

ideas = Table(
    'ideas', metadata,
    Column('id', Integer, primary_key=True),
    Column('title_encrypted', Text, nullable=False),
    Column('description_encrypted', Text),
    Column('content_encrypted', Text, nullable=False),
    Column('owner_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('team_id', Integer, ForeignKey('teams.id', ondelete='CASCADE'), index=True),
    Column('status', String(20), default='draft', index=True),
    Column('encryption_iv', String(64), nullable=False),
    Column('encryption_tag', String(64), nullable=False),
    Column('created_at', DateTime, server_default=func.now()),
    Column('updated_at', DateTime, server_default=func.now(), onupdate=func.now()),
    Column('is_deleted', Boolean, default=False),
    CheckConstraint(
        "status IN ('draft', 'in_progress', 'review', 'completed', 'archived')",
        name='chk_idea_status'
    )
)

idea_contributors = Table(
    'idea_contributors', metadata,
    Column('id', Integer, primary_key=True),
    Column('idea_id', Integer, ForeignKey('ideas.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('role', String(20), nullable=False),
    Column('added_at', DateTime, server_default=func.now()),
    Column('added_by', Integer, ForeignKey('users.id', ondelete='SET NULL')),
    CheckConstraint("role IN ('editor', 'commenter', 'viewer')", name='chk_contributor_role'),
    UniqueConstraint('idea_id', 'user_id', name='uq_idea_user')
)

idea_versions = Table(
    'idea_versions', metadata,
    Column('id', Integer, primary_key=True),
    Column('idea_id', Integer, ForeignKey('ideas.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('content_encrypted', Text, nullable=False),
    Column('encryption_iv', String(64), nullable=False),
    Column('encryption_tag', String(64), nullable=False),
    Column('version_number', Integer, nullable=False),
    Column('created_by', Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=False),
    Column('created_at', DateTime, server_default=func.now()),
    Column('change_description_encrypted', Text)
)

# =============================================================================
# Backup Tables
# =============================================================================

drive_backups = Table(
    'drive_backups', metadata,
    Column('id', Integer, primary_key=True),
    Column('backup_name', String(255), nullable=False),
    Column('backup_type', String(20), nullable=False),
    Column('owner_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('team_id', Integer, ForeignKey('teams.id', ondelete='CASCADE'), index=True),
    Column('backup_path', String(500), unique=True, nullable=False),
    Column('backup_size', BigInteger, nullable=False),
    Column('compressed_size', BigInteger, nullable=False),
    Column('encryption_iv', String(64), nullable=False),
    Column('encryption_tag', String(64), nullable=False),
    Column('checksum', Text, nullable=False),
    Column('file_count', Integer, default=0, nullable=False),
    Column('note_count', Integer, default=0, nullable=False),
    Column('idea_count', Integer, default=0, nullable=False),
    Column('status', String(20), default='completed', index=True),
    Column('created_at', DateTime, server_default=func.now(), index=True),
    Column('expires_at', DateTime),
    Column('is_deleted', Boolean, default=False),
    Column('metadata_encrypted', Text),
    CheckConstraint("backup_type IN ('full', 'incremental', 'differential')", name='chk_backup_type'),
    CheckConstraint(
        "status IN ('in_progress', 'completed', 'failed', 'expired')",
        name='chk_backup_status'
    ),
    CheckConstraint(
        "(team_id IS NULL AND owner_id IS NOT NULL) OR (team_id IS NOT NULL)",
        name='chk_backup_ownership'
    )
)

backup_schedules = Table(
    'backup_schedules', metadata,
    Column('id', Integer, primary_key=True),
    Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), index=True),
    Column('team_id', Integer, ForeignKey('teams.id', ondelete='CASCADE'), index=True),
    Column('schedule_name', String(255), nullable=False),
    Column('backup_type', String(20), nullable=False),
    Column('frequency', String(20), nullable=False),
    Column('retention_days', Integer, default=30, nullable=False),
    Column('is_active', Boolean, default=True),
    Column('last_backup_at', DateTime),
    Column('next_backup_at', DateTime, index=True),
    Column('created_at', DateTime, server_default=func.now()),
    Column('updated_at', DateTime, server_default=func.now(), onupdate=func.now()),
    CheckConstraint("backup_type IN ('full', 'incremental')", name='chk_schedule_backup_type'),
    CheckConstraint("frequency IN ('daily', 'weekly', 'monthly')", name='chk_schedule_frequency'),
    CheckConstraint(
        "(team_id IS NULL AND user_id IS NOT NULL) OR (team_id IS NOT NULL)",
        name='chk_schedule_ownership'
    )
)

# =============================================================================
# RBAC Tables
# =============================================================================

system_roles = Table(
    'system_roles', metadata,
    Column('id', Integer, primary_key=True),
    Column('name', String(50), unique=True, nullable=False),
    Column('display_name', String(100), nullable=False),
    Column('description', Text),
    Column('hierarchy_level', Integer, default=1, nullable=False),
    Column('is_system_role', Boolean, default=True),
    Column('created_at', DateTime, server_default=func.now()),
    Column('updated_at', DateTime, server_default=func.now(), onupdate=func.now()),
    CheckConstraint(
        "name IN ('super_admin', 'admin', 'content_manager', 'team_lead', 'creative_user', 'viewer')",
        name='chk_role_name'
    ),
    CheckConstraint('hierarchy_level BETWEEN 1 AND 6', name='chk_hierarchy_level')
)

system_permissions = Table(
    'system_permissions', metadata,
    Column('id', Integer, primary_key=True),
    Column('name', String(100), unique=True, nullable=False),
    Column('display_name', String(100), nullable=False),
    Column('description', Text),
    Column('category', String(50)),
    Column('created_at', DateTime, server_default=func.now())
)

role_permissions = Table(
    'role_permissions', metadata,
    Column('id', Integer, primary_key=True),
    Column('role_id', Integer, ForeignKey('system_roles.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('permission_id', Integer, ForeignKey('system_permissions.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('created_at', DateTime, server_default=func.now()),
    UniqueConstraint('role_id', 'permission_id', name='uq_role_permission')
)

user_system_roles = Table(
    'user_system_roles', metadata,
    Column('id', Integer, primary_key=True),
    Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('role_id', Integer, ForeignKey('system_roles.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('assigned_by', Integer, ForeignKey('users.id', ondelete='SET NULL')),
    Column('assigned_at', DateTime, server_default=func.now()),
    Column('expires_at', DateTime),
    Column('is_active', Boolean, default=True),
    UniqueConstraint('user_id', 'role_id', name='uq_user_role')
)

# =============================================================================
# Team Invitations and Notifications Tables
# =============================================================================

team_invitations = Table(
    'team_invitations', metadata,
    Column('id', Integer, primary_key=True),
    Column('team_id', Integer, ForeignKey('teams.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('inviter_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
    Column('invitee_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('status', String(20), default='pending', nullable=False, index=True),
    Column('message', Text),
    Column('created_at', DateTime, server_default=func.now()),
    Column('updated_at', DateTime, server_default=func.now(), onupdate=func.now()),
    Column('expires_at', DateTime, server_default=func.now() + datetime.timedelta(days=7), index=True),
    CheckConstraint(
        "status IN ('pending', 'accepted', 'rejected', 'cancelled')",
        name='chk_invitation_status'
    ),
    UniqueConstraint('team_id', 'invitee_id', 'status', name='uq_active_invitation')
)

notifications = Table(
    'notifications', metadata,
    Column('id', Integer, primary_key=True),
    Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
    Column('type', String(50), nullable=False, index=True),
    Column('title', String(255), nullable=False),
    Column('message', Text, nullable=False),
    Column('is_read', Boolean, default=False, index=True),
    Column('priority', String(20), default='normal'),
    Column('related_type', String(50)),
    Column('related_id', Integer),
    Column('action_url', String(500)),
    Column('created_at', DateTime, server_default=func.now(), index=True),
    Column('read_at', DateTime),
    Column('expires_at', DateTime, server_default=func.now() + datetime.timedelta(days=30)),
    CheckConstraint(
        "type IN ('team_invitation', 'team_invitation_accepted', 'team_invitation_rejected', "
        "'team_member_removed', 'team_role_changed', 'file_shared', 'message_received', 'system_alert')",
        name='chk_notification_type'
    ),
    CheckConstraint(
        "priority IN ('low', 'normal', 'high', 'urgent')",
        name='chk_notification_priority'
    )
)
