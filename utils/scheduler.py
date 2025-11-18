"""
utils/scheduler.py
Background task scheduler for maintenance operations
"""

import logging
import asyncio
from datetime import datetime
from typing import Callable
import os

logger = logging.getLogger(__name__)

# Scheduler configuration
SESSION_CLEANUP_INTERVAL_HOURS = int(os.getenv("SESSION_CLEANUP_INTERVAL_HOURS", "6"))


async def run_periodic_task(
    task_func: Callable,
    interval_seconds: int,
    task_name: str = "Periodic Task"
):
    """
    Run a task periodically in the background

    Args:
        task_func: Function to execute periodically
        interval_seconds: Interval between executions in seconds
        task_name: Name for logging
    """
    logger.info(f"Starting periodic task: {task_name} (interval: {interval_seconds}s)")

    while True:
        try:
            await asyncio.sleep(interval_seconds)

            logger.info(f"Running periodic task: {task_name}")
            result = task_func()

            if result is not None:
                logger.info(f"{task_name} completed: {result}")
            else:
                logger.info(f"{task_name} completed successfully")

        except Exception as e:
            logger.error(f"Error in periodic task {task_name}: {e}")


async def session_cleanup_task():
    """
    Background task to clean up expired sessions

    Runs every 6 hours by default (configurable via SESSION_CLEANUP_INTERVAL_HOURS)
    """
    from routers.auth import cleanup_expired_sessions

    interval_seconds = SESSION_CLEANUP_INTERVAL_HOURS * 3600

    await run_periodic_task(
        task_func=cleanup_expired_sessions,
        interval_seconds=interval_seconds,
        task_name="Session Cleanup"
    )


async def audit_log_cleanup_task():
    """
    Background task to clean up old audit logs

    Keeps logs for AUDIT_LOG_RETENTION_DAYS (default: 90 days)
    Runs daily
    """
    from database.connection import get_db_connection, return_db_connection

    retention_days = int(os.getenv("AUDIT_LOG_RETENTION_DAYS", "90"))
    interval_seconds = 24 * 3600  # 24 hours

    def cleanup_old_audit_logs():
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                DELETE FROM audit_logs
                WHERE created_at < NOW() - INTERVAL '%s days'
                """,
                (retention_days,)
            )

            deleted_count = cursor.rowcount
            conn.commit()
            return_db_connection(conn)

            logger.info(f"Audit log cleanup: removed {deleted_count} old entries")
            return deleted_count

        except Exception as e:
            logger.error(f"Audit log cleanup error: {e}")
            return 0

    await run_periodic_task(
        task_func=cleanup_old_audit_logs,
        interval_seconds=interval_seconds,
        task_name="Audit Log Cleanup"
    )


async def security_incidents_cleanup_task():
    """
    Background task to archive old security incidents

    Archives incidents older than SECURITY_INCIDENTS_RETENTION_DAYS (default: 365 days)
    Runs daily
    """
    from database.connection import get_db_connection, return_db_connection

    retention_days = int(os.getenv("SECURITY_INCIDENTS_RETENTION_DAYS", "365"))
    interval_seconds = 24 * 3600  # 24 hours

    def cleanup_old_security_incidents():
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Archive to separate table (optional) or just delete
            cursor.execute(
                """
                DELETE FROM security_incidents
                WHERE created_at < NOW() - INTERVAL '%s days'
                AND severity != 'critical'
                """,
                (retention_days,)
            )

            deleted_count = cursor.rowcount
            conn.commit()
            return_db_connection(conn)

            logger.info(f"Security incidents cleanup: removed {deleted_count} old entries")
            return deleted_count

        except Exception as e:
            logger.error(f"Security incidents cleanup error: {e}")
            return 0

    await run_periodic_task(
        task_func=cleanup_old_security_incidents,
        interval_seconds=interval_seconds,
        task_name="Security Incidents Cleanup"
    )


async def scheduled_backup_task():
    """
    Background task to execute scheduled backups

    Checks for scheduled backups that are due and executes them
    Runs every hour
    """
    from database.connection import get_db_connection, return_db_connection
    from utils.backup import (
        collect_user_data,
        collect_team_data,
        create_backup_manifest,
        create_encrypted_backup,
        calculate_backup_expiry
    )
    from utils.encryption import decrypt_user_key
    import time

    BACKUP_DIR = os.getenv("BACKUP_DIR", "./backups")
    interval_seconds = 3600  # Check every hour

    def execute_scheduled_backups():
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Get all active schedules that are due
            cursor.execute(
                """
                SELECT id, user_id, team_id, schedule_name, frequency, retention_days
                FROM backup_schedules
                WHERE is_active = TRUE
                AND (next_backup_at IS NULL OR next_backup_at <= NOW())
                """
            )

            due_schedules = cursor.fetchall()

            if not due_schedules:
                logger.info("No scheduled backups due")
                return 0

            logger.info(f"Found {len(due_schedules)} scheduled backups to execute")
            executed_count = 0

            for schedule in due_schedules:
                schedule_id, owner_user_id, team_id, schedule_name, frequency, retention_days = schedule

                try:
                    # Get encryption key
                    if team_id:
                        # Team backup - get team key from first admin/owner
                        cursor.execute(
                            """
                            SELECT user_id, team_key_encrypted FROM team_members
                            WHERE team_id = %s AND is_active = TRUE
                            AND role IN ('admin', 'owner')
                            LIMIT 1
                            """,
                            (team_id,)
                        )

                        team_member = cursor.fetchone()
                        if not team_member:
                            logger.error(f"No active team admin/owner for team {team_id}")
                            continue

                        user_id_for_backup = team_member[0]
                        encryption_key = decrypt_user_key(team_member[1])

                        # Collect team data
                        files, notes, ideas = collect_team_data(cursor, team_id, encryption_key)
                    else:
                        # User backup
                        cursor.execute(
                            "SELECT encryption_key FROM users WHERE id = %s",
                            (owner_user_id,)
                        )

                        user_row = cursor.fetchone()
                        if not user_row:
                            logger.error(f"User {owner_user_id} not found")
                            continue

                        user_id_for_backup = owner_user_id
                        encryption_key = decrypt_user_key(user_row[0])

                        # Collect user data
                        files, notes, ideas = collect_user_data(cursor, owner_user_id, encryption_key)

                    # Create manifest
                    manifest = create_backup_manifest(
                        files=files,
                        notes=notes,
                        ideas=ideas,
                        owner_id=user_id_for_backup,
                        team_id=team_id
                    )

                    # Create encrypted backup
                    ciphertext, iv, tag, checksum, original_size, compressed_size = create_encrypted_backup(
                        manifest=manifest,
                        encryption_key=encryption_key
                    )

                    # Save to disk
                    timestamp = int(time.time())
                    backup_filename = f"scheduled_{schedule_id}_{timestamp}.enc"
                    backup_path = os.path.join(BACKUP_DIR, backup_filename)

                    os.makedirs(BACKUP_DIR, exist_ok=True)
                    with open(backup_path, 'wb') as f:
                        f.write(ciphertext)

                    # Calculate expiry
                    expires_at = calculate_backup_expiry(retention_days)

                    # Save to database
                    cursor.execute(
                        """
                        INSERT INTO drive_backups (
                            backup_name, backup_type, owner_id, team_id,
                            backup_path, backup_size, compressed_size,
                            encryption_iv, encryption_tag, checksum,
                            file_count, note_count, idea_count,
                            expires_at, status
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'completed')
                        """,
                        (
                            f"{schedule_name} - {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                            "full",
                            user_id_for_backup,
                            team_id,
                            backup_path,
                            original_size,
                            compressed_size,
                            iv,
                            tag,
                            checksum,
                            len(files),
                            len(notes),
                            len(ideas),
                            expires_at
                        )
                    )

                    # Update schedule
                    from datetime import timedelta
                    next_backup = datetime.now()

                    if frequency == "daily":
                        next_backup += timedelta(days=1)
                    elif frequency == "weekly":
                        next_backup += timedelta(days=7)
                    elif frequency == "monthly":
                        next_backup += timedelta(days=30)

                    cursor.execute(
                        """
                        UPDATE backup_schedules
                        SET last_backup_at = NOW(), next_backup_at = %s, updated_at = NOW()
                        WHERE id = %s
                        """,
                        (next_backup, schedule_id)
                    )

                    conn.commit()
                    executed_count += 1

                    logger.info(
                        f"Scheduled backup {schedule_id} executed: {len(files)} files, "
                        f"{len(notes)} notes, {len(ideas)} ideas"
                    )

                except Exception as e:
                    logger.error(f"Failed to execute scheduled backup {schedule_id}: {e}")
                    conn.rollback()
                    continue

            return_db_connection(conn)

            logger.info(f"Executed {executed_count}/{len(due_schedules)} scheduled backups")
            return executed_count

        except Exception as e:
            logger.error(f"Scheduled backup task error: {e}")
            return 0

    await run_periodic_task(
        task_func=execute_scheduled_backups,
        interval_seconds=interval_seconds,
        task_name="Scheduled Backup Execution"
    )


async def backup_cleanup_task():
    """
    Background task to clean up expired backups

    Deletes expired backups from filesystem and database
    Runs daily
    """
    from utils.backup import cleanup_expired_backups

    interval_seconds = 24 * 3600  # 24 hours

    def cleanup_backups():
        try:
            from database.connection import get_db_connection, return_db_connection

            conn = get_db_connection()
            cursor = conn.cursor()

            deleted_count = cleanup_expired_backups(cursor)
            conn.commit()
            return_db_connection(conn)

            return deleted_count

        except Exception as e:
            logger.error(f"Backup cleanup error: {e}")
            return 0

    await run_periodic_task(
        task_func=cleanup_backups,
        interval_seconds=interval_seconds,
        task_name="Backup Cleanup"
    )


async def security_monitor_cleanup_task():
    """
    Background task to clean up old security event trackers

    Runs every 15 minutes to remove stale tracking data
    """
    from utils.security_monitor import cleanup_old_trackers

    interval_seconds = 15 * 60  # 15 minutes

    await run_periodic_task(
        task_func=cleanup_old_trackers,
        interval_seconds=interval_seconds,
        task_name="Security Monitor Cleanup"
    )


def start_background_tasks():
    """
    Start all background maintenance tasks

    Call this from main.py on application startup
    """
    import asyncio

    # Create event loop tasks
    tasks = [
        asyncio.create_task(session_cleanup_task()),
        asyncio.create_task(audit_log_cleanup_task()),
        asyncio.create_task(security_incidents_cleanup_task()),
        asyncio.create_task(scheduled_backup_task()),
        asyncio.create_task(backup_cleanup_task()),
        asyncio.create_task(security_monitor_cleanup_task()),
    ]

    logger.info(f"Started {len(tasks)} background maintenance tasks")

    return tasks
