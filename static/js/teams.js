/**
 * teams.js
 * Team invitation and notification functionality
 * Includes modal management, invitation sending, and real-time notifications
 */

// Global variables (use window scope to avoid redeclaration conflicts)
if (typeof window.currentTeamId === 'undefined') {
    window.currentTeamId = null;
}
if (typeof window.currentUserRole === 'undefined') {
    window.currentUserRole = null;
}
let notificationInterval = null;

// Modal Functions
function openInviteModal() {
    const modal = document.getElementById('inviteTeamModal');
    if (modal) {
        modal.style.display = 'block';
        document.getElementById('inviteUsername').value = '';
        document.getElementById('inviteMessage').value = '';
        document.getElementById('inviteError').style.display = 'none';
        document.getElementById('inviteSuccess').style.display = 'none';
    }
}

function closeInviteModal() {
    const modal = document.getElementById('inviteTeamModal');
    if (modal) {
        modal.style.display = 'none';
    }
    window.currentTeamId = null;
}

// Send Team Invitation
async function sendTeamInvitation() {
    const username = document.getElementById('inviteUsername').value.trim();
    const message = document.getElementById('inviteMessage').value.trim();
    const errorDiv = document.getElementById('inviteError');
    const successDiv = document.getElementById('inviteSuccess');

    // Reset messages
    errorDiv.style.display = 'none';
    successDiv.style.display = 'none';

    // Validate username
    if (!username) {
        errorDiv.textContent = 'Please enter a username';
        errorDiv.style.display = 'block';
        return;
    }

    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
        errorDiv.textContent = 'Username can only contain letters, numbers, underscores, and hyphens';
        errorDiv.style.display = 'block';
        return;
    }

    if (!window.currentTeamId) {
        errorDiv.textContent = 'No team selected';
        errorDiv.style.display = 'block';
        return;
    }

    try {
        // Get CSRF token from cookie
        const csrfCookie = document.cookie.split('; ').find(row => row.startsWith('csrf_token='));
        const csrfToken = csrfCookie ? csrfCookie.split('=')[1] : null;

        const headers = {
            'Content-Type': 'application/json'
        };

        if (csrfToken) {
            headers['X-CSRF-Token'] = csrfToken;
        }

        const response = await fetch(`/api/v1/teams/${window.currentTeamId}/invite`, {
            method: 'POST',
            credentials: 'same-origin',  // Session cookie sent automatically
            headers: headers,
            body: JSON.stringify({
                username: username,
                message: message || null
            })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            successDiv.textContent = data.message;
            successDiv.style.display = 'block';

            // Clear form and close after 2 seconds
            setTimeout(() => {
                closeInviteModal();
                // Show flash message
                if (typeof showFlashMessage === 'function') {
                    showFlashMessage(`Invitation sent to ${username}`, 'success');
                }
            }, 2000);
        } else {
            errorDiv.textContent = data.message || 'Failed to send invitation';
            errorDiv.style.display = 'block';
        }
    } catch (error) {
        console.error('Error sending invitation:', error);
        errorDiv.textContent = 'An error occurred. Please try again.';
        errorDiv.style.display = 'block';
    }
}

// Pending Invitations Functions
async function loadPendingInvitations() {
    try {
        // Session authentication via HTTP-only cookie (no token needed in JS)
        const response = await fetch('/api/v1/teams/invitations', {
            credentials: 'same-origin'  // Sends session cookie automatically
        });

        if (response.ok) {
            const data = await response.json();
            displayPendingInvitations(data.invitations);
        } else if (response.status === 401) {
            // Not authenticated - this is fine, user not logged in
            return;
        }
    } catch (error) {
        console.error('Error loading pending invitations:', error);
    }
}

function displayPendingInvitations(invitations) {
    const container = document.getElementById('pending-invitations-container');
    const listDiv = document.getElementById('invitations-list');

    if (!container || !listDiv) return;

    if (invitations.length === 0) {
        container.style.display = 'none';
        return;
    }

    container.style.display = 'block';
    listDiv.innerHTML = invitations.map(inv => `
        <li class="invitation-item" style="padding: 12px; background: var(--surface); border-radius: 8px; margin-bottom: 10px; border-left: 3px solid var(--accent);">
            <div style="margin-bottom: 8px;">
                <strong style="color: var(--text);">${escapeHtml(inv.team_name)}</strong>
            </div>
            <div style="font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 8px;">
                From: ${escapeHtml(inv.inviter_username)}
            </div>
            ${inv.message ? `<div style="font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 10px; font-style: italic;">"${escapeHtml(inv.message)}"</div>` : ''}
            <div style="display: flex; gap: 8px;">
                <button onclick="respondToInvitation(${inv.id}, 'accept')" class="btn btn-primary btn-sm" style="flex: 1; padding: 6px 12px; font-size: 0.875rem;">
                    Accept
                </button>
                <button onclick="respondToInvitation(${inv.id}, 'reject')" class="btn btn-secondary btn-sm" style="flex: 1; padding: 6px 12px; font-size: 0.875rem;">
                    Decline
                </button>
            </div>
        </li>
    `).join('');
}

async function respondToInvitation(invitationId, action) {
    try {
        // Get CSRF token from cookie
        const csrfCookie = document.cookie.split('; ').find(row => row.startsWith('csrf_token='));
        const csrfToken = csrfCookie ? csrfCookie.split('=')[1] : null;

        const headers = {
            'Content-Type': 'application/json'
        };

        if (csrfToken) {
            headers['X-CSRF-Token'] = csrfToken;
        }

        const response = await fetch(`/api/v1/teams/invitations/${invitationId}/respond`, {
            method: 'POST',
            credentials: 'same-origin',  // Sends session cookie automatically
            headers: headers,
            body: JSON.stringify({ action: action })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            if (typeof showFlashMessage === 'function') {
                showFlashMessage(
                    action === 'accept' ? 'Invitation accepted!' : 'Invitation declined',
                    'success'
                );
            }

            // Reload invitations and teams list
            await loadPendingInvitations();

            // Reload teams if accepted
            if (action === 'accept' && typeof loadUserTeams === 'function') {
                loadUserTeams();
            }
        } else {
            if (typeof showFlashMessage === 'function') {
                showFlashMessage(data.detail || 'Failed to respond to invitation', 'error');
            }
        }
    } catch (error) {
        console.error('Error responding to invitation:', error);
        if (typeof showFlashMessage === 'function') {
            showFlashMessage('An error occurred. Please try again.', 'error');
        }
    }
}

// Notification Functions
async function loadNotifications() {
    try {
        // Fetch both team notifications and unread message count in parallel
        const [notificationsResponse, messagesResponse] = await Promise.all([
            fetch('/api/v1/teams/notifications', {
                credentials: 'same-origin'
            }),
            fetch('/api/v1/messages/unread/count', {
                credentials: 'same-origin'
            }).catch(() => ({ ok: false })) // Graceful fallback if messages endpoint fails
        ]);

        let unreadTeamNotifications = 0;
        let unreadMessageCount = 0;

        // Process team notifications
        if (notificationsResponse.ok) {
            const data = await notificationsResponse.json();
            await displayNotifications(data.notifications);  // Now async
            unreadTeamNotifications = data.notifications.filter(n => !n.is_read).length;
        } else if (notificationsResponse.status === 401) {
            // Not authenticated - this is fine, user not logged in
            return;
        }

        // Process unread message count
        if (messagesResponse.ok) {
            const messageData = await messagesResponse.json();
            unreadMessageCount = messageData.unread_count || 0;
        }

        // Update badge with combined count
        const totalUnread = unreadTeamNotifications + unreadMessageCount;
        updateNotificationBadge(totalUnread);

        console.log('[Notifications] Team notifications:', unreadTeamNotifications, 'Messages:', unreadMessageCount, 'Total:', totalUnread);

    } catch (error) {
        console.error('Error loading notifications:', error);
    }
}

async function displayNotifications(notifications) {
    const listDiv = document.getElementById('notificationList');
    if (!listDiv) return;

    // Fetch unread messages to include in notifications
    let unreadMessages = [];
    try {
        const messagesResponse = await fetch('/api/v1/messages/inbox?unread_only=true', {
            credentials: 'same-origin'
        });
        if (messagesResponse.ok) {
            const messagesData = await messagesResponse.json();
            unreadMessages = messagesData.messages || [];
        }
    } catch (error) {
        console.error('Error fetching unread messages for notifications:', error);
    }

    // Combine team notifications and message notifications
    const allNotifications = [];

    // Add team notifications (only unread ones)
    notifications.forEach(n => {
        // Only show unread notifications
        if (!n.is_read) {
            allNotifications.push({
                type: 'team',
                id: n.id,
                is_read: n.is_read,
                title: n.title,
                message: n.message,
                created_at: n.created_at,
                action_url: n.action_url
            });
        }
    });

    // Add unread messages as notifications
    unreadMessages.forEach(msg => {
        allNotifications.push({
            type: 'message',
            id: msg.id,
            is_read: false,
            title: `New message from ${msg.sender_username}`,
            message: msg.content.length > 100 ? msg.content.substring(0, 100) + '...' : msg.content,
            created_at: msg.created_at,
            action_url: '/dashboard?tab=messages',
            sender_id: msg.sender_id
        });
    });

    // Sort by created_at (newest first)
    allNotifications.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    if (allNotifications.length === 0) {
        listDiv.innerHTML = '<div style="padding: 20px; text-align: center; color: #999;">No notifications</div>';
        return;
    }

    listDiv.innerHTML = allNotifications.map(n => {
        const clickHandler = n.type === 'team'
            ? `handleNotificationClick(${n.id}, '${escapeHtml(n.action_url || '')}')`
            : `handleMessageNotificationClick(${n.id}, ${n.sender_id})`;

        return `
            <div class="notification-item ${n.is_read ? '' : 'unread'}" onclick="${clickHandler}">
                <div class="notification-title">
                    ${n.type === 'message' ? '💬 ' : ''}${escapeHtml(n.title)}
                </div>
                <div class="notification-message">${escapeHtml(n.message)}</div>
                <div class="notification-time">${formatTime(n.created_at)}</div>
            </div>
        `;
    }).join('');
}

function updateNotificationBadge(count) {
    const badge = document.getElementById('notificationBadge');
    if (!badge) return;

    if (count > 0) {
        badge.textContent = count > 99 ? '99+' : count;
        badge.style.display = 'inline-block';
    } else {
        badge.style.display = 'none';
    }
}

async function handleNotificationClick(notificationId, actionUrl) {
    try {
        // Get CSRF token for PUT request
        const csrfCookie = document.cookie.split('; ').find(row => row.startsWith('csrf_token='));
        const csrfToken = csrfCookie ? csrfCookie.split('=')[1] : null;

        const headers = {};
        if (csrfToken) {
            headers['X-CSRF-Token'] = csrfToken;
        }

        // Mark as read (session cookie sent automatically)
        await fetch(`/api/v1/teams/notifications/${notificationId}/read`, {
            method: 'PUT',
            credentials: 'same-origin',
            headers: headers
        });

        // Reload notifications
        await loadNotifications();

        // Navigate if action URL exists
        if (actionUrl && actionUrl !== 'null' && actionUrl !== '') {
            window.location.href = actionUrl;
        }
    } catch (error) {
        console.error('Error handling notification click:', error);
    }
}

async function handleMessageNotificationClick(messageId, senderId) {
    try {
        // Mark message as read by fetching it (backend marks as read automatically)
        await fetch(`/api/v1/messages/${messageId}`, {
            credentials: 'same-origin'
        });

        // Reload notifications
        await loadNotifications();

        // Navigate to messages tab and open conversation
        window.location.href = '/dashboard?tab=messages';

        // If messages.js is loaded, try to open the conversation
        setTimeout(() => {
            if (typeof window.openConversation === 'function' && senderId) {
                // Fetch sender username
                fetch(`/api/v1/user/profile?user_id=${senderId}`, {
                    credentials: 'same-origin'
                }).then(res => res.json()).then(data => {
                    window.openConversation(senderId, data.username);
                }).catch(err => console.error('Failed to open conversation:', err));
            }
        }, 500);
    } catch (error) {
        console.error('Error handling message notification click:', error);
    }
}

function toggleNotifications() {
    const dropdown = document.getElementById('notificationDropdown');
    if (!dropdown) return;

    if (dropdown.style.display === 'none' || dropdown.style.display === '') {
        dropdown.style.display = 'block';
        loadNotifications(); // Refresh when opening
    } else {
        dropdown.style.display = 'none';
    }
}

async function markAllAsRead() {
    try {
        // Get CSRF token for PUT requests
        const csrfCookie = document.cookie.split('; ').find(row => row.startsWith('csrf_token='));
        const csrfToken = csrfCookie ? csrfCookie.split('=')[1] : null;

        const headers = {};
        if (csrfToken) {
            headers['X-CSRF-Token'] = csrfToken;
        }

        // Mark all team notifications as read
        const notificationsResponse = await fetch('/api/v1/teams/notifications?unread_only=true', {
            credentials: 'same-origin'
        });

        if (notificationsResponse.ok) {
            const data = await notificationsResponse.json();

            // Mark each team notification as read
            for (const notif of data.notifications) {
                await fetch(`/api/v1/teams/notifications/${notif.id}/read`, {
                    method: 'PUT',
                    credentials: 'same-origin',
                    headers: headers
                });
            }
        }

        // Mark all unread messages as read
        const messagesResponse = await fetch('/api/v1/messages/inbox?unread_only=true', {
            credentials: 'same-origin'
        });

        if (messagesResponse.ok) {
            const messagesData = await messagesResponse.json();

            // Mark each message as read by fetching it
            for (const msg of messagesData.messages) {
                await fetch(`/api/v1/messages/${msg.id}`, {
                    credentials: 'same-origin'
                });
            }
        }

        // Reload notifications
        await loadNotifications();

        // Show success message
        if (typeof showFlash === 'function') {
            showFlash('All notifications marked as read', 'success');
        } else if (typeof showFlashMessage === 'function') {
            showFlashMessage('All notifications marked as read', 'success');
        }

    } catch (error) {
        console.error('Error marking all as read:', error);
    }
}

// Team Management Functions
function setupTeamClickHandler(teamElement, teamId, teamData) {
    if (!teamElement) return;

    teamElement.addEventListener('click', () => {
        window.currentTeamId = teamId;
        window.currentUserRole = teamData.user_role || 'member';

        // Show team details
        const detailsPlaceholder = document.getElementById('team-details-placeholder');
        const detailsContent = document.getElementById('team-details-content');
        const teamName = document.getElementById('selected-team-name');
        const teamDescription = document.getElementById('selected-team-description');
        const inviteBtn = document.getElementById('invite-member-btn');
        const teamCallBtn = document.getElementById('start-team-call-btn');

        if (detailsPlaceholder) detailsPlaceholder.style.display = 'none';
        if (detailsContent) detailsContent.classList.remove('hidden');
        if (teamName) teamName.textContent = teamData.name || 'Team';
        if (teamDescription) teamDescription.textContent = teamData.description || 'No description provided.';

        // Show invite button only for owners/admins
        if (inviteBtn) {
            inviteBtn.style.display = (window.currentUserRole === 'owner' || window.currentUserRole === 'admin') ? 'flex' : 'none';
        }

        // Show team call button for all members
        if (teamCallBtn) {
            teamCallBtn.style.display = 'flex';
        }

        // Load team members
        loadTeamMembers(teamId);
    });
}

async function loadTeamMembers(teamId) {
    try {
        // Session cookie sent automatically
        const response = await fetch(`/api/v1/drive/teams/${teamId}/members`, {
            credentials: 'same-origin'
        });

        if (!response.ok) {
            console.error('Failed to load team members');
            return;
        }

        const data = await response.json();
        displayTeamMembers(data.members || []);
    } catch (error) {
        console.error('Error loading team members:', error);
    }
}

function displayTeamMembers(members) {
    const membersList = document.getElementById('team-members-list');
    if (!membersList) return;

    if (members.length === 0) {
        membersList.innerHTML = '<li style="padding: 20px; text-align: center; color: #999;">No members yet</li>';
        return;
    }

    membersList.innerHTML = members.map(member => `
        <li class="team-member-item">
            <div class="member-info">
                <span>${escapeHtml(member.username || 'Unknown')}</span>
                <span class="member-role-badge ${member.role}">${member.role}</span>
            </div>
            ${canRemoveMember(member) ? `
                <button class="btn-remove-member" onclick="removeMember(${member.user_id}, '${escapeHtml(member.username)}')">
                    Remove
                </button>
            ` : ''}
        </li>
    `).join('');
}

function canRemoveMember(member) {
    // Only owner/admin can remove members
    // Cannot remove yourself or the owner
    const currentUserId = parseInt(sessionStorage.getItem('user_id') || localStorage.getItem('user_id'));
    return (window.currentUserRole === 'owner' || window.currentUserRole === 'admin') &&
           member.role !== 'owner' &&
           member.user_id !== currentUserId;
}

async function removeMember(userId, username) {
    if (!confirm(`Are you sure you want to remove ${username} from the team?`)) {
        return;
    }

    try {
        // Get CSRF token for DELETE request
        const csrfCookie = document.cookie.split('; ').find(row => row.startsWith('csrf_token='));
        const csrfToken = csrfCookie ? csrfCookie.split('=')[1] : null;

        const headers = {};
        if (csrfToken) {
            headers['X-CSRF-Token'] = csrfToken;
        }

        // Session cookie sent automatically
        const response = await fetch(`/api/v1/teams/${window.currentTeamId}/members/${userId}`, {
            method: 'DELETE',
            credentials: 'same-origin',
            headers: headers
        });

        const data = await response.json();

        if (response.ok && data.success) {
            if (typeof showFlashMessage === 'function') {
                showFlashMessage(`Removed ${username} from team`, 'success');
            }
            // Reload team members
            loadTeamMembers(window.currentTeamId);
        } else {
            if (typeof showFlashMessage === 'function') {
                showFlashMessage(data.message || 'Failed to remove member', 'error');
            }
        }
    } catch (error) {
        console.error('Error removing member:', error);
        if (typeof showFlashMessage === 'function') {
            showFlashMessage('An error occurred. Please try again.', 'error');
        }
    }
}

// Global variable to store team being deleted
let teamToDelete = null;

function openDeleteTeamModal(teamId, teamName) {
    // Store team info for deletion
    teamToDelete = { id: teamId, name: teamName };

    // Show modal
    const modal = document.getElementById('delete-team-modal-overlay');
    const teamNameDisplay = document.getElementById('delete-team-name-display');
    const input = document.getElementById('delete-team-name-input');
    const confirmBtn = document.getElementById('confirm-delete-team-btn');

    if (modal) {
        modal.classList.add('active');
        modal.style.display = 'grid';
        if (teamNameDisplay) teamNameDisplay.textContent = teamName;
        if (input) {
            input.value = '';
            // Focus after a short delay to ensure modal is visible
            setTimeout(() => input.focus(), 100);
        }
        if (confirmBtn) confirmBtn.disabled = true;
    }
}

function closeDeleteTeamModal() {
    const modal = document.getElementById('delete-team-modal-overlay');
    const input = document.getElementById('delete-team-name-input');
    const confirmBtn = document.getElementById('confirm-delete-team-btn');

    if (modal) {
        modal.classList.remove('active');
        // Wait for animation before hiding
        setTimeout(() => {
            modal.style.display = 'none';
        }, 300);
    }
    if (input) input.value = '';
    if (confirmBtn) confirmBtn.disabled = true;

    teamToDelete = null;
}

function validateTeamDeletion() {
    const input = document.getElementById('delete-team-name-input');
    const confirmBtn = document.getElementById('confirm-delete-team-btn');

    if (input && confirmBtn && teamToDelete) {
        confirmBtn.disabled = input.value.trim() !== teamToDelete.name;
    }
}

async function confirmDeleteTeam() {
    if (!teamToDelete) {
        console.error('No team selected for deletion');
        return;
    }

    const { id: teamId, name: teamName } = teamToDelete;

    try {
        // Get CSRF token from cookie
        const csrfCookie = document.cookie.split('; ').find(row => row.startsWith('csrf_token='));
        const csrfToken = csrfCookie ? csrfCookie.split('=')[1] : null;

        if (!csrfToken) {
            console.error('CSRF token not found in cookies');
            const flashFunc = typeof showFlash === 'function' ? showFlash : (typeof showFlashMessage === 'function' ? showFlashMessage : null);
            if (flashFunc) {
                flashFunc('Security validation failed. Please refresh the page.', 'error');
            }
            closeDeleteTeamModal();
            return;
        }

        // Use session token from httpOnly cookie (sent automatically) + CSRF token
        const response = await fetch(`/api/v1/drive/teams/${teamId}`, {
            method: 'DELETE',
            credentials: 'same-origin',  // Include cookies
            headers: {
                'X-CSRF-Token': csrfToken  // CSRF protection
            }
        });

        const data = await response.json();

        if (response.ok) {
            const flashFunc = typeof showFlash === 'function' ? showFlash : (typeof showFlashMessage === 'function' ? showFlashMessage : null);
            if (flashFunc) {
                flashFunc(`Team "${teamName}" deleted successfully`, 'success');
            }

            // Close modal
            closeDeleteTeamModal();

            // Hide team details panel
            const detailsContent = document.getElementById('team-details-content');
            const detailsPlaceholder = document.getElementById('team-details-placeholder');
            if (detailsContent) detailsContent.classList.add('hidden');
            if (detailsPlaceholder) detailsPlaceholder.style.display = 'block';

            // Force full page refresh to update all team references
            // This ensures teams list, team drives sidebar, and all caches are properly updated
            setTimeout(() => {
                window.location.reload();
            }, 500); // Small delay to show the success message
        } else {
            const flashFunc = typeof showFlash === 'function' ? showFlash : (typeof showFlashMessage === 'function' ? showFlashMessage : null);
            if (flashFunc) {
                flashFunc(data.detail || 'Failed to delete team', 'error');
            }
            closeDeleteTeamModal();
        }
    } catch (error) {
        console.error('Error deleting team:', error);
        const flashFunc = typeof showFlash === 'function' ? showFlash : (typeof showFlashMessage === 'function' ? showFlashMessage : null);
        if (flashFunc) {
            flashFunc('An error occurred while deleting team. Please try again.', 'error');
        }
        closeDeleteTeamModal();
    }
}

// Keep legacy function name for backwards compatibility
async function deleteTeam(teamId, teamName) {
    openDeleteTeamModal(teamId, teamName);
}

// Utility Functions
function formatTime(isoString) {
    try {
        const date = new Date(isoString);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);

        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
        if (diffMins < 1440) {
            const hours = Math.floor(diffMins / 60);
            return `${hours} hour${hours > 1 ? 's' : ''} ago`;
        }
        return date.toLocaleDateString();
    } catch (error) {
        return 'Recently';
    }
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    // Load notifications and invitations on page load
    // Authentication happens via HTTP-only session cookie (sent automatically)
    loadNotifications();
    loadPendingInvitations();

    // Auto-refresh notifications every 30 seconds
    notificationInterval = setInterval(loadNotifications, 30000);
    // Auto-refresh invitations every 60 seconds
    setInterval(loadPendingInvitations, 60000);

    // Close modal when clicking outside
    window.addEventListener('click', (event) => {
        const modal = document.getElementById('inviteTeamModal');
        if (event.target === modal) {
            closeInviteModal();
        }

        const dropdown = document.getElementById('notificationDropdown');
        const bell = document.getElementById('notificationBell');
        if (dropdown && bell && !dropdown.contains(event.target) && !bell.contains(event.target)) {
            dropdown.style.display = 'none';
        }
    });

    // Handle Enter key in invite form
    const inviteUsername = document.getElementById('inviteUsername');
    const inviteMessage = document.getElementById('inviteMessage');
    if (inviteUsername) {
        inviteUsername.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                sendTeamInvitation();
            }
        });
    }

    // Wire up delete team modal validation
    const deleteTeamInput = document.getElementById('delete-team-name-input');
    if (deleteTeamInput) {
        deleteTeamInput.addEventListener('input', validateTeamDeletion);
        deleteTeamInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                const confirmBtn = document.getElementById('confirm-delete-team-btn');
                if (confirmBtn && !confirmBtn.disabled) {
                    confirmDeleteTeam();
                }
            }
        });
    }

    // Wire up delete team confirm button
    const confirmDeleteBtn = document.getElementById('confirm-delete-team-btn');
    if (confirmDeleteBtn) {
        confirmDeleteBtn.addEventListener('click', confirmDeleteTeam);
    }

    // Close delete modal when clicking outside
    const deleteTeamModal = document.getElementById('delete-team-modal-overlay');
    if (deleteTeamModal) {
        deleteTeamModal.addEventListener('click', (event) => {
            if (event.target === deleteTeamModal) {
                closeDeleteTeamModal();
            }
        });
    }
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (notificationInterval) {
        clearInterval(notificationInterval);
    }
});

// =============================================================================
// Team Video Calling Functionality
// =============================================================================

/**
 * Handle team call button click
 * Note: Team calls use the same infrastructure as direct messages
 * The user selects a team member to call
 */
async function handleTeamCallClick() {
    // Video calling feature will be fixed in the next release
    if (typeof showFlashMessage === 'function') {
        showFlashMessage('Video calling feature will be fixed in the next release. Stay tuned!', 'info');
    } else {
        // Fallback to window function if showFlashMessage is not available
        if (typeof window.showVideoCallComingSoon === 'function') {
            window.showVideoCallComingSoon();
        } else {
            alert('Video calling feature will be fixed in the next release. Stay tuned!');
        }
    }
}

/**
 * Initiate call to a team member
 * This reuses the video calling infrastructure from messages.js
 */
async function initiateTeamMemberCall(userId, username) {
    // Check if video calling is available
    if (typeof VideoAPIClient === 'undefined' || typeof SecureVideoCall === 'undefined') {
        if (typeof showFlashMessage === 'function') {
            showFlashMessage('Video calling is not available. Please refresh the page.', 'error');
        }
        return;
    }

    try {
        // Create API client and video call instance if not already exists
        if (!window.teamVideoCall) {
            const apiClient = new VideoAPIClient();
            window.teamVideoCall = new SecureVideoCall(apiClient);

            // Set up callbacks (same as messages.js)
            window.teamVideoCall.onLocalStream = (stream) => {
                const localVideo = document.getElementById('local-video');
                const localPlaceholder = document.getElementById('local-video-placeholder');
                if (localVideo) {
                    localVideo.srcObject = stream;
                    localVideo.style.display = 'block';
                    if (localPlaceholder) localPlaceholder.style.display = 'none';
                }
            };

            window.teamVideoCall.onRemoteStream = (stream) => {
                const remoteVideo = document.getElementById('remote-video');
                const remotePlaceholder = document.getElementById('remote-video-placeholder');
                if (remoteVideo) {
                    remoteVideo.srcObject = stream;
                    remoteVideo.style.display = 'block';
                    if (remotePlaceholder) remotePlaceholder.style.display = 'none';
                }
            };

            window.teamVideoCall.onCallEnded = (reason) => {
                console.log('Call ended:', reason);
                closeTeamVideoCallModal();
                if (typeof showFlashMessage === 'function') {
                    showFlashMessage('Call ended', 'info');
                }
            };

            window.teamVideoCall.onError = (error) => {
                console.error('Video call error:', error);
                if (typeof showFlashMessage === 'function') {
                    showFlashMessage('Call error: ' + error.message, 'error');
                }
            };

            window.teamVideoCall.onEncryptionVerified = (info) => {
                console.log('Encryption verified:', info);
                const encryptionIndicator = document.getElementById('encryption-indicator');
                if (encryptionIndicator) {
                    encryptionIndicator.style.display = 'inline-block';
                }
            };
        }

        // Open video call modal
        openTeamVideoCallModal(username, 'Calling...');

        // Start call
        const response = await window.teamVideoCall.startCall(userId, 'video');
        console.log('Team call initiated:', response);

        // Start call duration timer (reuse from messages.js if available)
        if (typeof window.startCallDurationTimer === 'function') {
            window.startCallDurationTimer();
        }

        if (typeof showFlashMessage === 'function') {
            showFlashMessage(`Calling ${username}...`, 'success');
        }

    } catch (error) {
        console.error('Failed to initiate team call:', error);
        closeTeamVideoCallModal();
        if (typeof showFlashMessage === 'function') {
            showFlashMessage('Failed to initiate call: ' + error.message, 'error');
        }
    }
}

/**
 * Open video call modal for team calls
 */
function openTeamVideoCallModal(memberName, status) {
    const videoCallOverlay = document.getElementById('video-call-overlay');
    const videoCallTitle = document.getElementById('video-call-title');
    const remoteParticipantName = document.getElementById('remote-participant-name');
    const remoteAvatar = document.getElementById('remote-avatar');

    if (videoCallTitle) videoCallTitle.textContent = `Team Call with ${memberName}`;
    if (remoteParticipantName) remoteParticipantName.textContent = status;
    if (remoteAvatar) remoteAvatar.textContent = memberName.substring(0, 2).toUpperCase();

    if (videoCallOverlay) {
        videoCallOverlay.style.display = 'flex';
    }
}

/**
 * Close team video call modal
 */
function closeTeamVideoCallModal() {
    const videoCallOverlay = document.getElementById('video-call-overlay');
    if (videoCallOverlay) {
        videoCallOverlay.style.display = 'none';
    }

    // Reset UI
    const localVideo = document.getElementById('local-video');
    const remoteVideo = document.getElementById('remote-video');
    const localPlaceholder = document.getElementById('local-video-placeholder');
    const remotePlaceholder = document.getElementById('remote-video-placeholder');
    const callDuration = document.getElementById('call-duration');
    const encryptionIndicator = document.getElementById('encryption-indicator');

    if (localVideo) {
        localVideo.srcObject = null;
        localVideo.style.display = 'none';
    }
    if (remoteVideo) {
        remoteVideo.srcObject = null;
        remoteVideo.style.display = 'none';
    }
    if (localPlaceholder) localPlaceholder.style.display = 'flex';
    if (remotePlaceholder) remotePlaceholder.style.display = 'flex';
    if (callDuration) callDuration.textContent = '00:00';
    if (encryptionIndicator) encryptionIndicator.style.display = 'none';
}

// Wire up team call button
document.addEventListener('DOMContentLoaded', () => {
    const teamCallBtn = document.getElementById('start-team-call-btn');
    if (teamCallBtn) {
        teamCallBtn.addEventListener('click', handleTeamCallClick);
    }
});

// Export functions for use in other scripts
window.openInviteModal = openInviteModal;
window.closeInviteModal = closeInviteModal;
window.sendTeamInvitation = sendTeamInvitation;
window.loadPendingInvitations = loadPendingInvitations;
window.respondToInvitation = respondToInvitation;
window.loadNotifications = loadNotifications;  // Export for messages.js to trigger updates
window.toggleNotifications = toggleNotifications;
window.handleNotificationClick = handleNotificationClick;
window.handleMessageNotificationClick = handleMessageNotificationClick;  // Export for message notifications
window.markAllAsRead = markAllAsRead;
window.setupTeamClickHandler = setupTeamClickHandler;
window.removeMember = removeMember;
window.loadTeamMembers = loadTeamMembers;
window.deleteTeam = deleteTeam;
window.openDeleteTeamModal = openDeleteTeamModal;
window.closeDeleteTeamModal = closeDeleteTeamModal;
window.confirmDeleteTeam = confirmDeleteTeam;
window.validateTeamDeletion = validateTeamDeletion;
