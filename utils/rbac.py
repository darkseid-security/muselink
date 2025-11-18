"""
utils/rbac.py
Role-Based Access Control (RBAC) System
Provides permission checking and role management for the application
"""

import logging
from enum import Enum
from typing import List, Set, Optional
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

logger = logging.getLogger(__name__)

security = HTTPBearer()

# ============================================================================
# ROLE AND PERMISSION ENUMS
# ============================================================================

class UserRole(str, Enum):
    """System roles"""
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    CONTENT_MANAGER = "content_manager"
    TEAM_LEAD = "team_lead"
    CREATIVE_USER = "creative_user"
    VIEWER = "viewer"


class Permission(str, Enum):
    """Granular permissions"""
    # System Administration
    MANAGE_SYSTEM_SETTINGS = "manage_system_settings"
    VIEW_SYSTEM_LOGS = "view_system_logs"
    MANAGE_INTEGRATIONS = "manage_integrations"

    # User Management
    CREATE_USER = "create_user"
    UPDATE_USER = "update_user"
    DELETE_USER = "delete_user"
    VIEW_ALL_USERS = "view_all_users"
    ASSIGN_ROLES = "assign_roles"

    # Content Management - Own
    CREATE_CONTENT = "create_content"
    UPDATE_OWN_CONTENT = "update_own_content"
    DELETE_OWN_CONTENT = "delete_own_content"
    VIEW_OWN_CONTENT = "view_own_content"

    # Content Management - Team
    VIEW_TEAM_CONTENT = "view_team_content"
    UPDATE_TEAM_CONTENT = "update_team_content"
    DELETE_TEAM_CONTENT = "delete_team_content"
    APPROVE_TEAM_CONTENT = "approve_team_content"

    # Content Management - All
    VIEW_ALL_CONTENT = "view_all_content"
    UPDATE_ALL_CONTENT = "update_all_content"
    DELETE_ALL_CONTENT = "delete_all_content"
    APPROVE_ALL_CONTENT = "approve_all_content"

    # Encrypted Drive
    MANAGE_OWN_FILES = "manage_own_files"
    MANAGE_TEAM_FILES = "manage_team_files"
    MANAGE_ALL_FILES = "manage_all_files"
    CREATE_BACKUP = "create_backup"
    RESTORE_BACKUP = "restore_backup"

    # Analytics & Reporting
    VIEW_OWN_ANALYTICS = "view_own_analytics"
    VIEW_TEAM_ANALYTICS = "view_team_analytics"
    VIEW_ALL_ANALYTICS = "view_all_analytics"
    EXPORT_REPORTS = "export_reports"

    # Audit & Security
    VIEW_AUDIT_LOGS = "view_audit_logs"
    MANAGE_SECURITY_SETTINGS = "manage_security_settings"
    VIEW_SECURITY_INCIDENTS = "view_security_incidents"


# ============================================================================
# PERMISSION CHECKING FUNCTIONS
# ============================================================================

def get_user_roles(cursor, user_id: int) -> List[str]:
    """
    Get all active roles for a user

    Args:
        cursor: Database cursor
        user_id: User ID

    Returns:
        List of role names
    """
    cursor.execute(
        """
        SELECT sr.name
        FROM user_system_roles usr
        JOIN system_roles sr ON usr.role_id = sr.id
        WHERE usr.user_id = %s
        AND usr.is_active = TRUE
        AND (usr.expires_at IS NULL OR usr.expires_at > NOW())
        """,
        (user_id,)
    )

    return [row[0] for row in cursor.fetchall()]


def get_role_permissions(cursor, role_name: str) -> Set[str]:
    """
    Get all permissions for a role

    Args:
        cursor: Database cursor
        role_name: Role name (e.g., 'admin', 'creative_user')

    Returns:
        Set of permission names
    """
    cursor.execute(
        """
        SELECT sp.name
        FROM role_permissions rp
        JOIN system_roles sr ON rp.role_id = sr.id
        JOIN system_permissions sp ON rp.permission_id = sp.id
        WHERE sr.name = %s
        """,
        (role_name,)
    )

    return {row[0] for row in cursor.fetchall()}


def get_user_permissions(cursor, user_id: int) -> Set[str]:
    """
    Get all permissions for a user (across all their roles)

    Args:
        cursor: Database cursor
        user_id: User ID

    Returns:
        Set of permission names
    """
    cursor.execute(
        """
        SELECT DISTINCT sp.name
        FROM user_system_roles usr
        JOIN role_permissions rp ON usr.role_id = rp.role_id
        JOIN system_permissions sp ON rp.permission_id = sp.id
        WHERE usr.user_id = %s
        AND usr.is_active = TRUE
        AND (usr.expires_at IS NULL OR usr.expires_at > NOW())
        """,
        (user_id,)
    )

    return {row[0] for row in cursor.fetchall()}


def has_permission(cursor, user_id: int, permission: Permission) -> bool:
    """
    Check if user has a specific permission

    Args:
        cursor: Database cursor
        user_id: User ID
        permission: Permission to check

    Returns:
        True if user has permission, False otherwise
    """
    user_permissions = get_user_permissions(cursor, user_id)
    return permission.value in user_permissions


def has_any_permission(cursor, user_id: int, permissions: List[Permission]) -> bool:
    """
    Check if user has ANY of the specified permissions

    Args:
        cursor: Database cursor
        user_id: User ID
        permissions: List of permissions to check

    Returns:
        True if user has at least one permission, False otherwise
    """
    user_permissions = get_user_permissions(cursor, user_id)
    return any(perm.value in user_permissions for perm in permissions)


def has_all_permissions(cursor, user_id: int, permissions: List[Permission]) -> bool:
    """
    Check if user has ALL of the specified permissions

    Args:
        cursor: Database cursor
        user_id: User ID
        permissions: List of permissions to check

    Returns:
        True if user has all permissions, False otherwise
    """
    user_permissions = get_user_permissions(cursor, user_id)
    return all(perm.value in user_permissions for perm in permissions)


def has_role(cursor, user_id: int, role: UserRole) -> bool:
    """
    Check if user has a specific role

    Args:
        cursor: Database cursor
        user_id: User ID
        role: Role to check

    Returns:
        True if user has role, False otherwise
    """
    user_roles = get_user_roles(cursor, user_id)
    return role.value in user_roles


def get_role_hierarchy_level(cursor, role_name: str) -> int:
    """
    Get hierarchical level of role (higher = more permissions)

    Args:
        cursor: Database cursor
        role_name: Role name

    Returns:
        Hierarchy level (1-6)
    """
    cursor.execute(
        "SELECT hierarchy_level FROM system_roles WHERE name = %s",
        (role_name,)
    )

    result = cursor.fetchone()
    return result[0] if result else 0


def can_assign_role(cursor, assigner_id: int, target_role: str) -> bool:
    """
    Check if a user can assign a specific role
    Users can only assign roles equal or lower in hierarchy

    Args:
        cursor: Database cursor
        assigner_id: ID of user trying to assign role
        target_role: Role name to be assigned

    Returns:
        True if assignment is allowed, False otherwise
    """
    assigner_roles = get_user_roles(cursor, assigner_id)

    if not assigner_roles:
        return False

    # Get highest hierarchy level of assigner
    assigner_levels = [get_role_hierarchy_level(cursor, role) for role in assigner_roles]
    max_assigner_level = max(assigner_levels) if assigner_levels else 0

    # Get target role level
    target_level = get_role_hierarchy_level(cursor, target_role)

    # Can assign if assigner's level is higher
    return max_assigner_level > target_level


# ============================================================================
# ROLE MANAGEMENT FUNCTIONS
# ============================================================================

def assign_role_to_user(cursor, user_id: int, role_name: str, assigned_by: int, expires_at: Optional[str] = None) -> int:
    """
    Assign a role to a user

    Args:
        cursor: Database cursor
        user_id: User ID to assign role to
        role_name: Role name to assign
        assigned_by: ID of user assigning the role
        expires_at: Optional expiration timestamp

    Returns:
        Assignment ID

    Raises:
        HTTPException: If role doesn't exist or user already has role
    """
    # Get role ID
    cursor.execute("SELECT id FROM system_roles WHERE name = %s", (role_name,))
    role_row = cursor.fetchone()

    if not role_row:
        raise HTTPException(404, detail=f"Role '{role_name}' not found")

    role_id = role_row[0]

    # Assign role
    cursor.execute(
        """
        INSERT INTO user_system_roles (user_id, role_id, assigned_by, expires_at)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (user_id, role_id) DO UPDATE
        SET is_active = TRUE, assigned_by = EXCLUDED.assigned_by, assigned_at = NOW()
        RETURNING id
        """,
        (user_id, role_id, assigned_by, expires_at)
    )

    assignment_id = cursor.fetchone()[0]
    logger.info(f"User {assigned_by} assigned role '{role_name}' to user {user_id}")

    return assignment_id


def revoke_role_from_user(cursor, user_id: int, role_name: str) -> bool:
    """
    Revoke a role from a user

    Args:
        cursor: Database cursor
        user_id: User ID to revoke role from
        role_name: Role name to revoke

    Returns:
        True if revoked, False if user didn't have role
    """
    cursor.execute(
        """
        UPDATE user_system_roles usr
        SET is_active = FALSE
        FROM system_roles sr
        WHERE usr.role_id = sr.id
        AND sr.name = %s
        AND usr.user_id = %s
        AND usr.is_active = TRUE
        RETURNING usr.id
        """,
        (role_name, user_id)
    )

    result = cursor.fetchone()

    if result:
        logger.info(f"Revoked role '{role_name}' from user {user_id}")
        return True

    return False


# ============================================================================
# PERMISSION DECORATORS & DEPENDENCIES
# ============================================================================

def require_permission(permission: Permission):
    """
    Dependency that requires a specific permission

    Usage:
        @router.get("/admin/users", dependencies=[Depends(require_permission(Permission.VIEW_ALL_USERS))])
        async def list_users():
            ...
    """
    async def permission_checker(
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ):
        from database.connection import get_db_connection
        from utils.security import verify_session_token

        # Verify session
        token = credentials.credentials
        user_id = verify_session_token(token)

        if not user_id:
            raise HTTPException(401, detail="Invalid session")

        # Check permission
        with get_db_connection() as conn:
            cursor = conn.cursor()

            if not has_permission(cursor, user_id, permission):
                raise HTTPException(
                    403,
                    detail=f"Missing required permission: {permission.value}"
                )

        return user_id

    return permission_checker


def require_role(role: UserRole):
    """
    Dependency that requires a specific role

    Usage:
        @router.get("/admin/dashboard", dependencies=[Depends(require_role(UserRole.ADMIN))])
        async def admin_dashboard():
            ...
    """
    async def role_checker(
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ):
        from database.connection import get_db_connection
        from utils.security import verify_session_token

        # Verify session
        token = credentials.credentials
        user_id = verify_session_token(token)

        if not user_id:
            raise HTTPException(401, detail="Invalid session")

        # Check role
        with get_db_connection() as conn:
            cursor = conn.cursor()

            if not has_role(cursor, user_id, role):
                raise HTTPException(
                    403,
                    detail=f"Required role: {role.value}"
                )

        return user_id

    return role_checker


def require_any_permission(permissions: List[Permission]):
    """
    Dependency that requires ANY of the specified permissions
    """
    async def permission_checker(
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ):
        from database.connection import get_db_connection
        from utils.security import verify_session_token

        token = credentials.credentials
        user_id = verify_session_token(token)

        if not user_id:
            raise HTTPException(401, detail="Invalid session")

        with get_db_connection() as conn:
            cursor = conn.cursor()

            if not has_any_permission(cursor, user_id, permissions):
                perm_names = [p.value for p in permissions]
                raise HTTPException(
                    403,
                    detail=f"Missing required permissions (need any of): {', '.join(perm_names)}"
                )

        return user_id

    return permission_checker


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_user_role_summary(cursor, user_id: int) -> dict:
    """
    Get summary of user's roles and permissions

    Args:
        cursor: Database cursor
        user_id: User ID

    Returns:
        Dictionary with roles, permissions, and hierarchy info
    """
    roles = get_user_roles(cursor, user_id)
    permissions = get_user_permissions(cursor, user_id)

    # Get hierarchy levels
    hierarchy_levels = {
        role: get_role_hierarchy_level(cursor, role)
        for role in roles
    }

    return {
        "user_id": user_id,
        "roles": roles,
        "permissions": sorted(list(permissions)),
        "hierarchy_levels": hierarchy_levels,
        "max_hierarchy_level": max(hierarchy_levels.values()) if hierarchy_levels else 0,
        "total_permissions": len(permissions)
    }


def list_all_roles(cursor) -> List[dict]:
    """
    List all system roles with their details

    Args:
        cursor: Database cursor

    Returns:
        List of role dictionaries
    """
    cursor.execute(
        """
        SELECT id, name, display_name, description, hierarchy_level, is_system_role
        FROM system_roles
        ORDER BY hierarchy_level DESC
        """
    )

    roles = []
    for row in cursor.fetchall():
        roles.append({
            "id": row[0],
            "name": row[1],
            "display_name": row[2],
            "description": row[3],
            "hierarchy_level": row[4],
            "is_system_role": row[5]
        })

    return roles


def list_all_permissions(cursor, category: Optional[str] = None) -> List[dict]:
    """
    List all system permissions, optionally filtered by category

    Args:
        cursor: Database cursor
        category: Optional category filter

    Returns:
        List of permission dictionaries
    """
    if category:
        cursor.execute(
            """
            SELECT id, name, display_name, description, category
            FROM system_permissions
            WHERE category = %s
            ORDER BY category, name
            """,
            (category,)
        )
    else:
        cursor.execute(
            """
            SELECT id, name, display_name, description, category
            FROM system_permissions
            ORDER BY category, name
            """
        )

    permissions = []
    for row in cursor.fetchall():
        permissions.append({
            "id": row[0],
            "name": row[1],
            "display_name": row[2],
            "description": row[3],
            "category": row[4]
        })

    return permissions
