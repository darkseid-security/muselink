/**
 * messages.js
 * Encrypted messaging functionality
 * Handles conversation list, message rendering, compose, and delete
 */

// Global state for messaging
let currentConversationUserId = null;
let messagesPollingInterval = null;

// Format timestamp for messages
function formatMessageTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;

    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;

    const diffDays = Math.floor(diffHours / 24);
    if (diffDays < 7) return `${diffDays}d ago`;

    return date.toLocaleDateString();
}

// Format full timestamp
function formatFullTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        hour12: true
    });
}

// Get CSRF token from cookies
function getCSRFToken() {
    const csrfCookie = document.cookie.split('; ').find(row => row.startsWith('csrf_token='));
    return csrfCookie ? csrfCookie.split('=')[1] : null;
}

// API calls for messages
const MessagesAPI = {
    async getInbox() {
        // Session cookie sent automatically via credentials: 'same-origin'
        const response = await fetch('/api/v1/messages/inbox', {
            credentials: 'same-origin'
        });
        if (response.status === 429) {
            console.warn('Rate limit hit for inbox, will retry later');
            return { messages: [] }; // Return empty to avoid crashing
        }
        if (!response.ok) throw new Error('Failed to fetch inbox');
        return await response.json();
    },

    async getSent() {
        // Session cookie sent automatically via credentials: 'same-origin'
        const response = await fetch('/api/v1/messages/sent', {
            credentials: 'same-origin'
        });
        if (response.status === 429) {
            console.warn('Rate limit hit for sent messages, will retry later');
            return { messages: [] }; // Return empty to avoid crashing
        }
        if (!response.ok) throw new Error('Failed to fetch sent messages');
        return await response.json();
    },

    async getMessage(messageId) {
        // Session cookie sent automatically via credentials: 'same-origin'
        const response = await fetch(`/api/v1/messages/${messageId}`, {
            credentials: 'same-origin'
        });
        if (!response.ok) throw new Error('Failed to fetch message');
        return await response.json();
    },

    async sendMessage(receiverId, subject, content) {
        const csrfToken = getCSRFToken();
        const headers = {
            'Content-Type': 'application/json'
        };
        if (csrfToken) {
            headers['X-CSRF-Token'] = csrfToken;
        }

        const response = await fetch('/api/v1/messages/send', {
            method: 'POST',
            credentials: 'same-origin',  // Session cookie sent automatically
            headers: headers,
            body: JSON.stringify({
                receiver_id: receiverId,
                subject: subject,
                content: content
            })
        });
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to send message');
        }
        return await response.json();
    },

    async deleteMessage(messageId) {
        const csrfToken = getCSRFToken();
        const headers = {};
        if (csrfToken) {
            headers['X-CSRF-Token'] = csrfToken;
        }

        const response = await fetch(`/api/v1/messages/${messageId}`, {
            method: 'DELETE',
            credentials: 'same-origin',  // Session cookie sent automatically
            headers: headers
        });
        if (!response.ok) throw new Error('Failed to delete message');
        return await response.json();
    },

    async getUnreadCount() {
        // Session cookie sent automatically via credentials: 'same-origin'
        const response = await fetch('/api/v1/messages/unread/count', {
            credentials: 'same-origin'
        });
        if (!response.ok) throw new Error('Failed to fetch unread count');
        return await response.json();
    },

    async getTeamMembers() {
        // Get all team members the user can message (via team access control)
        const response = await fetch('/api/v1/drive/teams', {
            credentials: 'same-origin'
        });
        if (!response.ok) throw new Error('Failed to fetch teams');
        return await response.json();
    }
};

// Render conversation list
async function renderConversationList() {
    const conversationList = document.getElementById('conversation-list');
    if (!conversationList) return;

    try {
        // Show loading state
        conversationList.innerHTML = '<div class="loading-state" style="padding: 2rem; text-align: center;"><p>Loading conversations...</p></div>';

        // Fetch inbox and sent messages
        const [inboxData, sentData] = await Promise.all([
            MessagesAPI.getInbox(),
            MessagesAPI.getSent()
        ]);

        const allMessages = [...inboxData.messages, ...sentData.messages];

        if (allMessages.length === 0) {
            conversationList.innerHTML = '';
            return;
        }

        // Get current user ID - try multiple sources
        let currentUserId = window.cache?.currentUser?.id;

        // If not in cache, fetch from API
        if (!currentUserId) {
            try {
                const profileResponse = await fetch('/api/v1/user/profile', {
                    credentials: 'same-origin'
                });
                if (profileResponse.ok) {
                    const profileData = await profileResponse.json();
                    currentUserId = profileData.id;
                    // Update cache
                    if (!window.cache) window.cache = {};
                    if (!window.cache.currentUser) window.cache.currentUser = {};
                    window.cache.currentUser.id = currentUserId;
                }
            } catch (error) {
                console.error('[Messages] Failed to fetch user profile:', error);
            }
        }

        console.log('[Messages] Current user ID for conversation list:', currentUserId);

        // Group messages by conversation partner
        const conversations = {};
        allMessages.forEach(msg => {
            // Ensure type consistency
            const msgSenderId = parseInt(msg.sender_id);
            const msgReceiverId = parseInt(msg.receiver_id);
            const currentUserIdInt = parseInt(currentUserId);

            const partnerId = msgSenderId === currentUserIdInt ? msgReceiverId : msgSenderId;
            const partnerName = msgSenderId === currentUserIdInt ? msg.receiver_username : msg.sender_username;

            if (!conversations[partnerId]) {
                conversations[partnerId] = {
                    partnerId,
                    partnerName,
                    messages: [],
                    unreadCount: 0
                };
            }

            conversations[partnerId].messages.push(msg);

            // Count unread messages (received by current user and not read)
            if (msgReceiverId === currentUserIdInt && !msg.is_read) {
                conversations[partnerId].unreadCount++;
            }
        });

        // Sort conversations by most recent message
        const sortedConversations = Object.values(conversations).sort((a, b) => {
            const lastA = Math.max(...a.messages.map(m => new Date(m.created_at).getTime()));
            const lastB = Math.max(...b.messages.map(m => new Date(m.created_at).getTime()));
            return lastB - lastA;
        });

        // Escape HTML helper
        const escapeHtml = (text) => {
            const div = document.createElement('div');
            div.textContent = text || '';
            return div.innerHTML;
        };

        // Render conversations
        conversationList.innerHTML = sortedConversations.map(conv => {
            const lastMessage = conv.messages.sort((a, b) =>
                new Date(b.created_at) - new Date(a.created_at)
            )[0];

            return `
                <div class="conversation-item ${conv.partnerId === currentConversationUserId ? 'active' : ''}"
                     data-user-id="${conv.partnerId}"
                     data-username="${escapeHtml(conv.partnerName)}">
                    <div class="conversation-avatar">${escapeHtml(conv.partnerName.substring(0, 2).toUpperCase())}</div>
                    <div class="conversation-info">
                        <div class="conversation-header">
                            <h4>${escapeHtml(conv.partnerName)}</h4>
                            <span class="conversation-time">${formatMessageTime(lastMessage.created_at)}</span>
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        // Add click handlers
        conversationList.querySelectorAll('.conversation-item').forEach(item => {
            item.addEventListener('click', () => {
                const userId = parseInt(item.dataset.userId);
                const username = item.dataset.username;
                openConversation(userId, username);
            });
        });

    } catch (error) {
        console.error('Error rendering conversation list:', error);
        conversationList.innerHTML = `
            <div style="padding: 2rem; text-align: center; color: var(--error);">
                <p>Failed to load conversations</p>
                <button class="btn btn-sm btn-secondary" onclick="renderConversationList()" style="margin-top: 1rem;">Retry</button>
            </div>
        `;
    }
}

// Open a conversation
async function openConversation(userId, username) {
    currentConversationUserId = userId;

    // Update UI
    const chatPlaceholder = document.getElementById('chat-placeholder');
    const chatView = document.getElementById('chat-view');
    const chatTitle = document.getElementById('chat-title');
    const chatSubtitle = document.getElementById('chat-subtitle');
    const startVideoCallBtn = document.getElementById('start-video-call-btn');
    const startConversationBtn = document.getElementById('start-conversation-btn');

    if (chatPlaceholder) chatPlaceholder.classList.add('hidden');
    if (chatView) chatView.classList.remove('hidden');
    if (chatTitle) chatTitle.textContent = username;
    if (chatSubtitle) chatSubtitle.textContent = 'End-to-end encrypted conversation';

    // Show both buttons inline
    if (startVideoCallBtn) startVideoCallBtn.style.display = 'flex';
    if (startConversationBtn) startConversationBtn.style.display = 'flex';

    // Update active conversation in list
    document.querySelectorAll('.conversation-item').forEach(item => {
        item.classList.toggle('active', parseInt(item.dataset.userId) === userId);
    });

    // Load messages
    await loadConversationMessages(userId);

    // Start polling for new messages (every 15 seconds to avoid rate limits)
    if (messagesPollingInterval) {
        clearInterval(messagesPollingInterval);
    }
    messagesPollingInterval = setInterval(() => {
        if (currentConversationUserId === userId) {
            loadConversationMessages(userId, true);
        }
    }, 15000);
}

// Load messages for a conversation
async function loadConversationMessages(userId, silent = false) {
    const messagesList = document.getElementById('chat-messages-list');
    if (!messagesList) return;

    try {
        if (!silent) {
            messagesList.innerHTML = '<div class="loading-state" style="padding: 2rem; text-align: center;"><p>Loading messages...</p></div>';
        }

        // Fetch inbox and sent messages
        const [inboxData, sentData] = await Promise.all([
            MessagesAPI.getInbox(),
            MessagesAPI.getSent()
        ]);

        // Get current user ID - try multiple sources
        let currentUserId = window.cache?.currentUser?.id;

        // If not in cache, fetch from API
        if (!currentUserId) {
            try {
                const profileResponse = await fetch('/api/v1/user/profile', {
                    credentials: 'same-origin'
                });
                if (profileResponse.ok) {
                    const profileData = await profileResponse.json();
                    currentUserId = profileData.id;
                    // Update cache
                    if (!window.cache) window.cache = {};
                    if (!window.cache.currentUser) window.cache.currentUser = {};
                    window.cache.currentUser.id = currentUserId;
                }
            } catch (error) {
                console.error('[Messages] Failed to fetch user profile:', error);
            }
        }

        console.log('[Messages] Loading conversation for userId:', userId, 'currentUserId:', currentUserId);

        // Filter messages for this conversation
        const allMessages = [...inboxData.messages, ...sentData.messages];

        console.log('[Messages] All messages:', allMessages);
        console.log('[Messages] Filtering for conversation between', currentUserId, 'and', userId);

        const conversationMessages = allMessages.filter(msg => {
            // Ensure type consistency - parse to integers
            const msgSenderId = parseInt(msg.sender_id);
            const msgReceiverId = parseInt(msg.receiver_id);
            const currentUserIdInt = parseInt(currentUserId);
            const userIdInt = parseInt(userId);

            const match = (msgSenderId === currentUserIdInt && msgReceiverId === userIdInt) ||
                         (msgSenderId === userIdInt && msgReceiverId === currentUserIdInt);

            if (match) {
                console.log('[Messages] Message matched:', msg.id, 'sender:', msgSenderId, 'receiver:', msgReceiverId);
            }

            return match;
        });

        // Sort by timestamp
        conversationMessages.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));

        if (conversationMessages.length === 0) {
            messagesList.innerHTML = `
                <div style="padding: 2rem; text-align: center; color: var(--text-secondary);">
                    <p>No messages yet. Start the conversation!</p>
                </div>
            `;
            return;
        }

        // Debug log messages
        console.log('[Messages] Rendering conversation messages:', conversationMessages);

        // Render messages
        messagesList.innerHTML = conversationMessages.map(msg => {
            const isSent = parseInt(msg.sender_id) === parseInt(currentUserId);
            const messageClass = isSent ? 'message-sent' : 'message-received';

            // Debug log individual message
            console.log('[Messages] Rendering message:', {
                id: msg.id,
                sender_id: msg.sender_id,
                receiver_id: msg.receiver_id,
                content: msg.content,
                contentLength: msg.content ? msg.content.length : 0
            });

            // Escape HTML in content to prevent XSS
            const escapeHtml = (text) => {
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            };

            const content = msg.content ? escapeHtml(msg.content) : '[No content]';

            return `
                <div class="message-wrapper ${messageClass}">
                    <div class="message-bubble">
                        ${msg.subject ? `<div class="message-subject">${escapeHtml(msg.subject)}</div>` : ''}
                        <div class="message-content">${content}</div>
                        <div class="message-meta">
                            <span class="message-time">${formatFullTimestamp(msg.created_at)}</span>
                            ${isSent ? `
                                <button class="message-delete-btn" data-message-id="${msg.id}" title="Delete message">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                        <polyline points="3 6 5 6 21 6"></polyline>
                                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                                    </svg>
                                </button>
                            ` : ''}
                            ${msg.is_read && isSent ? '<span class="message-read-status" title="Read">✓✓</span>' : ''}
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        // Add delete handlers
        messagesList.querySelectorAll('.message-delete-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                e.stopPropagation();
                const messageId = parseInt(btn.dataset.messageId);
                await deleteMessage(messageId);
            });
        });

        // Scroll to bottom
        messagesList.scrollTop = messagesList.scrollHeight;

        // Don't refresh conversation list during polling to reduce API calls
        // Only refresh on initial load or user actions

    } catch (error) {
        console.error('Error loading conversation messages:', error);
        messagesList.innerHTML = `
            <div style="padding: 2rem; text-align: center; color: var(--error);">
                <p>Failed to load messages</p>
            </div>
        `;
    }
}

// Send a message
async function sendMessage(event) {
    event.preventDefault();

    const input = document.getElementById('chat-message-input');
    const content = input.value.trim();

    if (!content || !currentConversationUserId) return;

    try {
        // Disable input while sending
        input.disabled = true;

        await MessagesAPI.sendMessage(currentConversationUserId, null, content);

        // Clear input
        input.value = '';
        input.disabled = false;
        input.focus();

        // Reload messages
        await loadConversationMessages(currentConversationUserId);

        // Update conversation list
        await renderConversationList();

        // NOTE: Don't update notification bell when sending messages
        // Bell should only show received messages, not sent ones

    } catch (error) {
        console.error('Error sending message:', error);
        input.disabled = false;

        // Show error using flash message if available
        if (typeof showFlash === 'function') {
            showFlash('Failed to send message: ' + error.message, 'error');
        } else {
            alert('Failed to send message: ' + error.message);
        }
    }
}

// Delete a message
async function deleteMessage(messageId) {
    if (!confirm('Are you sure you want to delete this message? This action cannot be undone.')) {
        return;
    }

    try {
        await MessagesAPI.deleteMessage(messageId);

        // Show success message
        if (typeof showFlash === 'function') {
            showFlash('Message deleted successfully', 'success');
        }

        // Reload current conversation
        if (currentConversationUserId) {
            await loadConversationMessages(currentConversationUserId);
        }

        // Update conversation list
        await renderConversationList();

    } catch (error) {
        console.error('Error deleting message:', error);
        if (typeof showFlash === 'function') {
            showFlash('Failed to delete message: ' + error.message, 'error');
        } else {
            alert('Failed to delete message');
        }
    }
}

// Open start conversation modal
function openStartConversationModal() {
    const modal = document.getElementById('start-conversation-modal');
    const overlay = modal?.closest('.modal-overlay');

    if (modal && overlay) {
        // Populate recipient select with all users
        populateRecipientSelect();

        overlay.classList.add('active');
        modal.classList.add('active');
    }
}

// Populate recipient select dropdown
async function populateRecipientSelect() {
    const select = document.getElementById('conversation-recipient');
    if (!select) return;

    try {
        select.innerHTML = '<option value="">Loading...</option>';

        // Get current user ID - try multiple sources
        let currentUserId = window.cache?.currentUser?.id;

        // If not in cache, fetch from API
        if (!currentUserId) {
            try {
                const profileResponse = await fetch('/api/v1/user/profile', {
                    credentials: 'same-origin'
                });
                if (profileResponse.ok) {
                    const profileData = await profileResponse.json();
                    currentUserId = profileData.id;
                    // Update cache
                    if (!window.cache) window.cache = {};
                    if (!window.cache.currentUser) window.cache.currentUser = {};
                    window.cache.currentUser.id = currentUserId;
                }
            } catch (error) {
                console.error('[Messages] Failed to fetch user profile:', error);
            }
        }

        console.log('[Messages] Current user ID:', currentUserId);

        // Fetch teams data to get all team members
        const teamsData = await MessagesAPI.getTeamMembers();
        console.log('[Messages] Teams data:', teamsData);

        const users = new Map();

        // Collect all unique team members across all teams
        for (const team of teamsData.teams || []) {
            console.log(`[Messages] Fetching members for team ${team.id} (${team.name})`);

            try {
                // Fetch team members for each team
                const response = await fetch(`/api/v1/drive/teams/${team.id}/members`, {
                    credentials: 'same-origin'
                });

                if (response.ok) {
                    const membersData = await response.json();
                    console.log(`[Messages] Team ${team.id} members:`, membersData);

                    membersData.members.forEach(member => {
                        if (member.user_id !== currentUserId && !users.has(member.user_id)) {
                            console.log(`[Messages] Adding user: ${member.username} (ID: ${member.user_id})`);
                            users.set(member.user_id, member.username);
                        }
                    });
                } else {
                    console.error(`[Messages] Failed to fetch members for team ${team.id}: ${response.status}`);
                }
            } catch (error) {
                console.error(`[Messages] Error loading members for team ${team.id}:`, error);
            }
        }

        console.log('[Messages] Final users map:', Array.from(users.entries()));

        if (users.size === 0) {
            select.innerHTML = '<option value="">No team members available</option>';
            return;
        }

        // Sort users alphabetically
        const sortedUsers = Array.from(users.entries()).sort((a, b) =>
            a[1].localeCompare(b[1])
        );

        select.innerHTML = '<option value="">Select a team member...</option>' +
            sortedUsers.map(([id, name]) =>
                `<option value="${id}">${name}</option>`
            ).join('');

    } catch (error) {
        console.error('[Messages] Error loading users:', error);
        select.innerHTML = '<option value="">Failed to load team members</option>';
    }
}

// Handle start conversation form
async function handleStartConversation(event) {
    event.preventDefault();

    const select = document.getElementById('conversation-recipient');
    const userId = parseInt(select.value);
    const username = select.options[select.selectedIndex].text;

    if (!userId) {
        if (typeof showFlash === 'function') {
            showFlash('Please select a recipient', 'warning');
        }
        return;
    }

    // Close modal
    const modal = document.getElementById('start-conversation-modal');
    const overlay = modal?.closest('.modal-overlay');
    if (overlay) overlay.classList.remove('active');
    if (modal) modal.classList.remove('active');

    // Open conversation
    await openConversation(userId, username);
}

// Initialize messages functionality
function initializeMessages() {
    // Handle message send form
    const chatForm = document.getElementById('chat-input-form');
    if (chatForm) {
        chatForm.addEventListener('submit', sendMessage);
    }

    // Handle start conversation button
    const startConversationBtn = document.getElementById('start-conversation-btn');
    if (startConversationBtn) {
        startConversationBtn.addEventListener('click', openStartConversationModal);
    }

    // Handle start conversation form
    const startConversationForm = document.getElementById('start-conversation-form');
    if (startConversationForm) {
        startConversationForm.addEventListener('submit', handleStartConversation);
    }

    // Cleanup on page unload
    window.addEventListener('beforeunload', () => {
        if (messagesPollingInterval) {
            clearInterval(messagesPollingInterval);
        }
    });
}

// Export functions for use in user-dashboard.js
window.renderConversationList = renderConversationList;
window.openConversation = openConversation;
window.initializeMessages = initializeMessages;
window.MessagesAPI = MessagesAPI;

// =============================================================================
// Video Calling Functionality
// =============================================================================

let videoCall = null;
let currentCallId = null;
let callDurationInterval = null;
let callStartTime = null;

/**
 * Initialize video calling functionality
 */
function initializeVideoCalling() {
    // Create API client and video call instance
    const apiClient = new VideoAPIClient();
    videoCall = new SecureVideoCall(apiClient);

    // Set up callbacks
    videoCall.onLocalStream = (stream) => {
        const localVideo = document.getElementById('local-video');
        const localPlaceholder = document.getElementById('local-video-placeholder');
        if (localVideo) {
            localVideo.srcObject = stream;
            localVideo.style.display = 'block';
            if (localPlaceholder) localPlaceholder.style.display = 'none';
        }
    };

    videoCall.onRemoteStream = (stream) => {
        const remoteVideo = document.getElementById('remote-video');
        const remotePlaceholder = document.getElementById('remote-video-placeholder');
        if (remoteVideo) {
            remoteVideo.srcObject = stream;
            remoteVideo.style.display = 'block';
            if (remotePlaceholder) remotePlaceholder.style.display = 'none';
        }
    };

    videoCall.onCallEnded = (reason) => {
        console.log('Call ended:', reason);
        closeVideoCallModal();
        if (typeof showFlash === 'function') {
            showFlash('Call ended', 'info');
        }
    };

    videoCall.onError = (error) => {
        console.error('Video call error:', error);
        if (typeof showFlash === 'function') {
            showFlash('Call error: ' + error.message, 'error');
        }
    };

    videoCall.onEncryptionVerified = (info) => {
        console.log('Encryption verified:', info);
        const encryptionIndicator = document.getElementById('encryption-indicator');
        if (encryptionIndicator) {
            encryptionIndicator.style.display = 'inline-block';
        }
    };

    // Set up UI event handlers
    // Video call feature disabled - will be fixed in next release
    // const startVideoCallBtn = document.getElementById('start-video-call-btn');
    // if (startVideoCallBtn) {
    //     startVideoCallBtn.addEventListener('click', initiateVideoCall);
    // }

    const endCallBtn = document.getElementById('end-call-btn');
    if (endCallBtn) {
        endCallBtn.addEventListener('click', async () => {
            await videoCall.endCall();
            closeVideoCallModal();
        });
    }

    const closeVideoCallBtn = document.getElementById('close-video-call');
    if (closeVideoCallBtn) {
        closeVideoCallBtn.addEventListener('click', async () => {
            if (confirm('Are you sure you want to end the call?')) {
                await videoCall.endCall();
                closeVideoCallModal();
            }
        });
    }

    const toggleMicBtn = document.getElementById('toggle-mic-btn');
    if (toggleMicBtn) {
        toggleMicBtn.addEventListener('click', () => {
            const isEnabled = videoCall.toggleAudio();
            toggleMicBtn.setAttribute('data-muted', isEnabled ? 'false' : 'true');
            toggleMicBtn.style.background = isEnabled ? '' : '#ff6b6b';
        });
    }

    const toggleCameraBtn = document.getElementById('toggle-camera-btn');
    if (toggleCameraBtn) {
        toggleCameraBtn.addEventListener('click', () => {
            const isEnabled = videoCall.toggleVideo();
            toggleCameraBtn.setAttribute('data-video-off', isEnabled ? 'false' : 'true');
            toggleCameraBtn.style.background = isEnabled ? '' : '#ff6b6b';

            // Show/hide local video
            const localVideo = document.getElementById('local-video');
            const localPlaceholder = document.getElementById('local-video-placeholder');
            if (localVideo && localPlaceholder) {
                localVideo.style.display = isEnabled ? 'block' : 'none';
                localPlaceholder.style.display = isEnabled ? 'none' : 'flex';
            }
        });
    }

    // Incoming call handlers
    const acceptCallBtn = document.getElementById('accept-call-btn');
    const rejectCallBtn = document.getElementById('reject-call-btn');

    if (acceptCallBtn) {
        acceptCallBtn.addEventListener('click', acceptIncomingCall);
    }

    if (rejectCallBtn) {
        rejectCallBtn.addEventListener('click', rejectIncomingCall);
    }
}

/**
 * Initiate video call to current conversation partner
 */
async function initiateVideoCall() {
    if (!currentConversationUserId) {
        if (typeof showFlash === 'function') {
            showFlash('Please select a conversation first', 'warning');
        }
        return;
    }

    try {
        // Get conversation partner's name
        const chatTitle = document.getElementById('chat-title');
        const partnerName = chatTitle ? chatTitle.textContent : 'User';

        // Show call modal
        openVideoCallModal(partnerName, 'Calling...');

        // Start call
        const response = await videoCall.startCall(currentConversationUserId, 'video');
        console.log('Call initiated:', response);

        // Start call duration timer
        startCallDurationTimer();

        if (typeof showFlash === 'function') {
            showFlash('Call initiated successfully', 'success');
        }

    } catch (error) {
        console.error('Failed to initiate call:', error);
        closeVideoCallModal();
        if (typeof showFlash === 'function') {
            showFlash('Failed to initiate call: ' + error.message, 'error');
        }
    }
}

/**
 * Accept incoming call
 */
async function acceptIncomingCall() {
    if (!currentCallId) return;

    try {
        // Close incoming call modal
        const incomingCallOverlay = document.getElementById('incoming-call-overlay');
        if (incomingCallOverlay) {
            incomingCallOverlay.style.display = 'none';
        }

        // Get caller info from incoming call modal
        const incomingCallName = document.getElementById('incoming-call-name');
        const callerName = incomingCallName ? incomingCallName.textContent : 'User';

        // Open video call modal
        openVideoCallModal(callerName, 'Connected');

        // Answer call
        await videoCall.answerCall(currentCallId);

        // Start call duration timer
        startCallDurationTimer();

        if (typeof showFlash === 'function') {
            showFlash('Call accepted', 'success');
        }

    } catch (error) {
        console.error('Failed to accept call:', error);
        closeVideoCallModal();
        if (typeof showFlash === 'function') {
            showFlash('Failed to accept call: ' + error.message, 'error');
        }
    }
}

/**
 * Reject incoming call
 */
async function rejectIncomingCall() {
    if (!currentCallId) return;

    try {
        await videoCall.rejectCall(currentCallId);

        // Close incoming call modal
        const incomingCallOverlay = document.getElementById('incoming-call-overlay');
        if (incomingCallOverlay) {
            incomingCallOverlay.style.display = 'none';
        }

        currentCallId = null;

        if (typeof showFlash === 'function') {
            showFlash('Call declined', 'info');
        }

    } catch (error) {
        console.error('Failed to reject call:', error);
        if (typeof showFlash === 'function') {
            showFlash('Failed to reject call: ' + error.message, 'error');
        }
    }
}

/**
 * Show incoming call modal
 */
function showIncomingCallModal(callId, callerName, callType) {
    currentCallId = callId;

    const incomingCallOverlay = document.getElementById('incoming-call-overlay');
    const incomingCallName = document.getElementById('incoming-call-name');
    const incomingCallType = document.getElementById('incoming-call-type');
    const incomingCallAvatar = document.getElementById('incoming-call-avatar');

    if (incomingCallName) incomingCallName.textContent = callerName;
    if (incomingCallType) incomingCallType.textContent = callType === 'video' ? 'Video Call' : 'Audio Call';
    if (incomingCallAvatar) incomingCallAvatar.textContent = callerName.substring(0, 2).toUpperCase();

    if (incomingCallOverlay) {
        incomingCallOverlay.style.display = 'flex';
    }
}

/**
 * Open video call modal
 */
function openVideoCallModal(partnerName, status) {
    const videoCallOverlay = document.getElementById('video-call-overlay');
    const videoCallTitle = document.getElementById('video-call-title');
    const remoteParticipantName = document.getElementById('remote-participant-name');
    const remoteAvatar = document.getElementById('remote-avatar');

    if (videoCallTitle) videoCallTitle.textContent = `Call with ${partnerName}`;
    if (remoteParticipantName) remoteParticipantName.textContent = status;
    if (remoteAvatar) remoteAvatar.textContent = partnerName.substring(0, 2).toUpperCase();

    if (videoCallOverlay) {
        videoCallOverlay.style.display = 'flex';
    }
}

/**
 * Close video call modal
 */
function closeVideoCallModal() {
    const videoCallOverlay = document.getElementById('video-call-overlay');
    if (videoCallOverlay) {
        videoCallOverlay.style.display = 'none';
    }

    // Stop call duration timer
    if (callDurationInterval) {
        clearInterval(callDurationInterval);
        callDurationInterval = null;
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

    callStartTime = null;
    currentCallId = null;
}

/**
 * Start call duration timer
 */
function startCallDurationTimer() {
    callStartTime = Date.now();

    if (callDurationInterval) {
        clearInterval(callDurationInterval);
    }

    callDurationInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - callStartTime) / 1000);
        const minutes = Math.floor(elapsed / 60);
        const seconds = elapsed % 60;

        const callDuration = document.getElementById('call-duration');
        if (callDuration) {
            callDuration.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        }
    }, 1000);
}

// Initialize video calling when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeVideoCalling);
} else {
    initializeVideoCalling();
}
