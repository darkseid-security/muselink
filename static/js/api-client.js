/**
 * API Client for Genesis AI Platform
 * Handles all backend API communications
 *
 * SECURITY: Uses HTTP-only cookies for authentication
 * NO localStorage/sessionStorage token storage (XSS protection)
 */

class APIClient {
    constructor() {
        this.baseURL = window.location.origin + '/api/v1';
        // NO token storage - session managed via HTTP-only cookies
    }

    // Helper to get CSRF token from cookie
    getCSRFToken() {
        const csrfCookie = document.cookie.split('; ').find(row => row.startsWith('csrf_token='));
        return csrfCookie ? csrfCookie.split('=')[1] : null;
    }

    // Helper method for API requests
    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const csrfToken = this.getCSRFToken();

        const headers = {
            'Content-Type': 'application/json',
            ...(csrfToken && { 'X-CSRF-Token': csrfToken }),  // Include CSRF token if present
            ...options.headers
        };

        const config = {
            ...options,
            headers,
            credentials: 'include'  // CRITICAL: Send cookies with request
        };

        try {
            const response = await fetch(url, config);

            if (response.status === 401) {
                // Session expired or invalid
                window.location.href = '/auth';
                throw new Error('Session expired');
            }

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || data.error || 'Request failed');
            }

            return data;
        } catch (error) {
            console.error('API Request Error:', error);
            throw error;
        }
    }

    // Authentication Methods
    async getCaptcha() {
        return this.request('/auth/captcha', { method: 'GET', skipAuth: true });
    }

    async register(userData, captchaHash) {
        return this.request(`/auth/register?captcha_hash=${captchaHash}`, {
            method: 'POST',
            body: JSON.stringify(userData),
            skipAuth: true
        });
    }

    async login(credentials, captchaHash) {
        // Server sets HTTP-only cookie automatically
        // NO client-side token storage
        const data = await this.request(`/auth/login?captcha_hash=${captchaHash}`, {
            method: 'POST',
            body: JSON.stringify(credentials),
            skipAuth: true
        });

        // Server handles session via HTTP-only cookie
        // Client receives only user info (no tokens)
        return data;
    }

    async verifyMFA(mfaCode, sessionToken) {
        // Server sets HTTP-only cookie automatically
        // NO client-side token storage
        const data = await this.request('/auth/mfa/verify', {
            method: 'POST',
            body: JSON.stringify({
                mfa_code: mfaCode,
                session_token: sessionToken
            }),
            skipAuth: true
        });

        // Server handles session via HTTP-only cookie
        // Client receives only user info (no tokens)
        return data;
    }

    async logout() {
        // Server clears HTTP-only cookie
        try {
            await this.request('/auth/logout', {
                method: 'POST'
            });
        } catch (error) {
            console.error('Logout error:', error);
        }

        // Redirect to auth page
        window.location.href = '/auth';
    }

    // User Profile Methods
    async getProfile() {
        return this.request('/user/profile', { method: 'GET' });
    }

    async updateProfile(profileData) {
        return this.request('/user/profile', {
            method: 'PUT',
            body: JSON.stringify(profileData)
        });
    }

    async changePassword(passwordData) {
        return this.request('/user/change-password', {
            method: 'POST',
            body: JSON.stringify(passwordData)
        });
    }

    async changeEmail(emailData) {
        return this.request('/user/settings/change-email', {
            method: 'POST',
            body: JSON.stringify(emailData)
        });
    }

    // MFA Methods (using auth.py endpoints)
    async getMFAStatus() {
        return this.request('/user/settings/mfa/status', { method: 'GET' });
    }

    async setupMFA() {
        // GET /api/v1/auth/mfa/setup - generates QR code and secret
        return this.request('/auth/mfa/setup', { method: 'GET' });
    }

    async enableMFA(mfaCode) {
        // POST /api/v1/auth/mfa/enable - verifies code and enables MFA
        return this.request('/auth/mfa/enable', {
            method: 'POST',
            body: JSON.stringify({ mfa_code: mfaCode })
        });
    }

    async disableMFA(password, mfaCode) {
        // POST /api/v1/auth/mfa/disable - disables MFA (requires password + MFA code)
        return this.request('/auth/mfa/disable', {
            method: 'POST',
            body: JSON.stringify({
                password: password,
                mfa_code: mfaCode
            })
        });
    }

    // Creative Content Methods
    async submitBrief(briefData) {
        return this.request('/creative/brief', {
            method: 'POST',
            body: JSON.stringify(briefData)
        });
    }

    async getBriefs(limit = 20, offset = 0) {
        return this.request(`/creative/briefs?limit=${limit}&offset=${offset}`, {
            method: 'GET'
        });
    }

    async getBriefDrafts(briefId) {
        return this.request(`/creative/brief/${briefId}/drafts`, { method: 'GET' });
    }

    async getDraft(draftId) {
        return this.request(`/creative/draft/${draftId}`, { method: 'GET' });
    }

    async refineDraft(draftId, refinementNotes) {
        return this.request(`/creative/draft/${draftId}/refine?refinement_notes=${encodeURIComponent(refinementNotes)}`, {
            method: 'POST'
        });
    }

    async submitFeedback(feedbackData) {
        return this.request('/creative/draft/feedback', {
            method: 'POST',
            body: JSON.stringify(feedbackData)
        });
    }

    async getAnalytics() {
        return this.request('/creative/analytics', { method: 'GET' });
    }

    // Drive Methods
    async createTeam(teamData) {
        return this.request('/drive/teams', {
            method: 'POST',
            body: JSON.stringify(teamData)
        });
    }

    async getTeams() {
        return this.request('/drive/teams', { method: 'GET' });
    }

    async addTeamMember(teamId, memberData) {
        return this.request(`/drive/teams/${teamId}/members`, {
            method: 'POST',
            body: JSON.stringify(memberData)
        });
    }

    async uploadFile(file, folderId = null, teamId = null) {
        const formData = new FormData();
        formData.append('file', file);
        
        let url = '/drive/files/upload';
        const params = new URLSearchParams();
        if (folderId) params.append('folder_id', folderId);
        if (teamId) params.append('team_id', teamId);
        if (params.toString()) url += `?${params.toString()}`;

        const response = await fetch(`${this.baseURL}${url}`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${this.token}`
            },
            body: formData
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Upload failed');
        }

        return response.json();
    }

    async downloadFile(fileId) {
        const response = await fetch(`${this.baseURL}/drive/files/${fileId}/download`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${this.token}`
            }
        });

        if (!response.ok) {
            throw new Error('Download failed');
        }

        return response.blob();
    }

    async createNote(noteData) {
        return this.request('/drive/notes', {
            method: 'POST',
            body: JSON.stringify(noteData)
        });
    }

    async getNotes(teamId = null, folderId = null) {
        let url = '/drive/notes';
        const params = new URLSearchParams();
        if (teamId) params.append('team_id', teamId);
        if (folderId) params.append('folder_id', folderId);
        if (params.toString()) url += `?${params.toString()}`;

        return this.request(url, { method: 'GET' });
    }

    async getNote(noteId) {
        return this.request(`/drive/notes/${noteId}`, { method: 'GET' });
    }

    async updateNote(noteId, noteData) {
        return this.request(`/drive/notes/${noteId}`, {
            method: 'PUT',
            body: JSON.stringify(noteData)
        });
    }

    async createIdea(ideaData) {
        return this.request('/drive/ideas', {
            method: 'POST',
            body: JSON.stringify(ideaData)
        });
    }

    async getIdeas(teamId = null) {
        let url = '/drive/ideas';
        if (teamId) url += `?team_id=${teamId}`;
        return this.request(url, { method: 'GET' });
    }

    async getIdea(ideaId) {
        return this.request(`/drive/ideas/${ideaId}`, { method: 'GET' });
    }

    async updateIdea(ideaId, ideaData) {
        return this.request(`/drive/ideas/${ideaId}`, {
            method: 'PUT',
            body: JSON.stringify(ideaData)
        });
    }

    // Messages Methods
    async sendMessage(messageData) {
        return this.request('/messages/send', {
            method: 'POST',
            body: JSON.stringify(messageData)
        });
    }

    async getInbox(unreadOnly = false) {
        return this.request(`/messages/inbox?unread_only=${unreadOnly}`, {
            method: 'GET'
        });
    }

    async getSentMessages() {
        return this.request('/messages/sent', { method: 'GET' });
    }

    async getMessage(messageId) {
        return this.request(`/messages/${messageId}`, { method: 'GET' });
    }

    async deleteMessage(messageId) {
        return this.request(`/messages/${messageId}`, { method: 'DELETE' });
    }

    async getUnreadCount() {
        return this.request('/messages/unread/count', { method: 'GET' });
    }

    // Video Calling Methods
    async initiateCall(receiverId, callType = 'video') {
        return this.request('/video/call/initiate', {
            method: 'POST',
            body: JSON.stringify({
                receiver_id: receiverId,
                call_type: callType
            })
        });
    }

    async respondToCall(callId, action) {
        return this.request('/video/call/respond', {
            method: 'POST',
            body: JSON.stringify({
                call_id: callId,
                action: action
            })
        });
    }

    async endCall(callId) {
        return this.request(`/video/call/${callId}/end`, { method: 'POST' });
    }

    async getCallHistory(limit = 20, offset = 0) {
        return this.request(`/video/call/history?limit=${limit}&offset=${offset}`, {
            method: 'GET'
        });
    }

    async getOnlineUsers() {
        return this.request('/video/online/users', { method: 'GET' });
    }

    // WebSocket for video signaling
    connectSignaling() {
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsURL = `${wsProtocol}//${window.location.host}/api/v1/video/ws/signaling?token=${this.token}`;
        return new WebSocket(wsURL);
    }
}

// Export singleton instance
const apiClient = new APIClient();
window.apiClient = apiClient;
