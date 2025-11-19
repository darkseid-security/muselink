"""
utils/team_access.py
Team-based access control utilities

Security: Ensures users can only communicate with members of their shared teams
"""

import logging
from typing import List, Tuple
from database.models import team_members
from database.sqlalchemy_db import execute_query
from sqlalchemy import select, and_

logger = logging.getLogger(__name__)


def check_users_share_team(user1_id: int, user2_id: int) -> Tuple[bool, List[int]]:
    """
    Check if two users share at least one team

    Args:
        user1_id: ID of first user
        user2_id: ID of second user

    Returns:
        Tuple of (bool: users share team(s), list of shared team IDs)

    Security: Prevents unauthorized communication between non-team members
    """
    try:
        # Get all team IDs for user1
        user1_teams = execute_query(
            select(team_members.c.team_id)
            .where(team_members.c.user_id == user1_id),
            fetch_all=True
        )
        user1_team_ids = [row[0] for row in user1_teams] if user1_teams else []

        if not user1_team_ids:
            # User1 not in any teams
            return False, []

        # Get all team IDs for user2
        user2_teams = execute_query(
            select(team_members.c.team_id)
            .where(team_members.c.user_id == user2_id),
            fetch_all=True
        )
        user2_team_ids = [row[0] for row in user2_teams] if user2_teams else []

        if not user2_team_ids:
            # User2 not in any teams
            return False, []

        # Find intersection of team IDs
        shared_team_ids = list(set(user1_team_ids) & set(user2_team_ids))

        if shared_team_ids:
            logger.info(
                f"Users {user1_id} and {user2_id} share {len(shared_team_ids)} team(s): {shared_team_ids}"
            )
            return True, shared_team_ids
        else:
            logger.warning(
                f"Users {user1_id} and {user2_id} do not share any teams "
                f"(user1: {user1_team_ids}, user2: {user2_team_ids})"
            )
            return False, []

    except Exception as e:
        logger.error(f"Error checking team membership: {type(e).__name__} - {str(e)}")
        # Fail secure: deny access if check fails
        return False, []


def get_user_team_members(user_id: int) -> List[int]:
    """
    Get all user IDs that share at least one team with the given user

    Args:
        user_id: User ID to check

    Returns:
        List of user IDs that share teams with the given user

    Security: Used to populate allowed contacts lists
    """
    try:
        # Get all teams the user belongs to
        user_teams = execute_query(
            select(team_members.c.team_id)
            .where(team_members.c.user_id == user_id),
            fetch_all=True
        )

        user_team_ids = [row[0] for row in user_teams] if user_teams else []

        if not user_team_ids:
            return []

        # Get all users in those teams (excluding the current user)
        team_member_users = execute_query(
            select(team_members.c.user_id)
            .where(
                and_(
                    team_members.c.team_id.in_(user_team_ids),
                    team_members.c.user_id != user_id
                )
            )
            .distinct(),
            fetch_all=True
        )

        member_ids = [row[0] for row in team_member_users] if team_member_users else []

        logger.info(f"User {user_id} can communicate with {len(member_ids)} team members")

        return member_ids

    except Exception as e:
        logger.error(f"Error getting team members: {type(e).__name__} - {str(e)}")
        return []


def verify_team_access(user_id: int, target_user_id: int, action: str = "communicate") -> bool:
    """
    Verify that a user has permission to interact with another user based on team membership

    Args:
        user_id: ID of user initiating action
        target_user_id: ID of target user
        action: Description of action (for logging)

    Returns:
        True if access granted, False otherwise

    Raises:
        None - returns False for failed access checks

    Security:
        - Zero-knowledge: Only checks team membership, not team content
        - Audit logging for denied access attempts
        - Fail-secure: Returns False on any errors
    """
    try:
        shares_team, shared_teams = check_users_share_team(user_id, target_user_id)

        if not shares_team:
            logger.warning(
                f"ACCESS DENIED: User {user_id} attempted to {action} with user {target_user_id} "
                f"but they do not share any teams"
            )
            return False

        logger.info(
            f"ACCESS GRANTED: User {user_id} can {action} with user {target_user_id} "
            f"(shared teams: {shared_teams})"
        )
        return True

    except Exception as e:
        logger.error(f"Team access verification error: {type(e).__name__} - {str(e)}")
        # Fail secure
        return False
