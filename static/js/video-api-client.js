/**
 * Video Call API Client
 * Provides API wrapper for encrypted video calling with team-based access control
 */

class VideoAPIClient {
    constructor() {
        this.baseURL = '/api/v1/video';
    }

    /**
     * Get CSRF token from cookie
     */
    getCSRFToken() {
        const name = 'csrf_token=';
        const decodedCookie = decodeURIComponent(document.cookie);
        const ca = decodedCookie.split(';');
        for (let i = 0; i < ca.length; i++) {
            let c = ca[i].trim();
            if (c.indexOf(name) === 0) {
                return c.substring(name.length, c.length);
            }
        }
        return null;
    }

    /**
     * Check if user is authenticated
     * Note: Session token is in HTTP-only cookie, so we can't access it directly
     * We check for CSRF token presence as a proxy for authentication
     * The actual session validation happens server-side
     */
    isAuthenticated() {
        // HTTP-only cookies can't be read by JavaScript
        // We check if CSRF token exists (non-HTTP-only) as a proxy for authentication
        // The browser will automatically send the session_token cookie with requests
        const csrfToken = this.getCSRFToken();
        return csrfToken !== null;
    }

    /**
     * Initiate a video/audio call
     */
    async initiateCall(receiverId, callType = 'video') {
        // Check if authenticated
        if (!this.isAuthenticated()) {
            throw new Error('Not authenticated');
        }

        const csrfToken = this.getCSRFToken();

        const response = await fetch(`${this.baseURL}/call/initiate`, {
            method: 'POST',
            credentials: 'same-origin',  // Send HTTP-only cookies automatically
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken  // CSRF protection
            },
            body: JSON.stringify({
                receiver_id: receiverId,
                call_type: callType,
                encryption_required: true
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || error.detail || 'Failed to initiate call');
        }

        return await response.json();
    }

    /**
     * Respond to incoming call (accept/reject)
     */
    async respondToCall(callId, action) {
        if (!this.isAuthenticated()) {
            throw new Error('Not authenticated');
        }

        const csrfToken = this.getCSRFToken();

        const response = await fetch(`${this.baseURL}/call/respond`, {
            method: 'POST',
            credentials: 'same-origin',  // Send HTTP-only cookies automatically
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken  // CSRF protection
            },
            body: JSON.stringify({
                call_id: callId,
                action: action  // 'accept' or 'reject'
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to respond to call');
        }

        return await response.json();
    }

    /**
     * End active call
     */
    async endCall(callId) {
        if (!this.isAuthenticated()) {
            throw new Error('Not authenticated');
        }

        const csrfToken = this.getCSRFToken();

        const response = await fetch(`${this.baseURL}/call/${callId}/end`, {
            method: 'POST',
            credentials: 'same-origin',  // Send HTTP-only cookies automatically
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken  // CSRF protection
            }
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to end call');
        }

        return await response.json();
    }

    /**
     * Connect to WebSocket signaling server
     */
    connectSignaling() {
        if (!this.isAuthenticated()) {
            throw new Error('Not authenticated');
        }

        // Determine WebSocket URL based on current location
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host;
        const wsURL = `${protocol}//${host}/api/v1/video/ws/signaling`;

        // WebSocket will include cookies automatically for same-origin connections
        // The server will validate the session_token cookie
        const ws = new WebSocket(wsURL);

        return ws;
    }

    /**
     * Get call history
     */
    async getCallHistory(limit = 20, offset = 0) {
        if (!this.isAuthenticated()) {
            throw new Error('Not authenticated');
        }

        const response = await fetch(`${this.baseURL}/call/history?limit=${limit}&offset=${offset}`, {
            method: 'GET',
            credentials: 'same-origin'  // Send HTTP-only cookies automatically
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to get call history');
        }

        return await response.json();
    }

    /**
     * Get online users
     */
    async getOnlineUsers() {
        if (!this.isAuthenticated()) {
            throw new Error('Not authenticated');
        }

        const response = await fetch(`${this.baseURL}/online/users`, {
            method: 'GET',
            credentials: 'same-origin'  // Send HTTP-only cookies automatically
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to get online users');
        }

        return await response.json();
    }
}

// Export for use
window.VideoAPIClient = VideoAPIClient;
