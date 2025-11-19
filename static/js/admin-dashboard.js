/**
 * Admin Dashboard JavaScript
 * Handles data fetching, display, and interactions
 */

// ===== 1. STATE MANAGEMENT =====
const state = {
    currentPage: 'overview-page',
    incidentsPage: 0,
    auditPage: 0,
    usersPage: 0,
    incidentsSeverity: '',
    incidentsType: '',
    auditAction: '',
    userSearch: ''
};

const PAGE_SIZE = 50;

// ===== 2. UTILITY FUNCTIONS =====
// Authentication is handled via HTTP-only cookies server-side
// No need for client-side token management

function showFlashMessage(title, message, type = 'info') {
    const container = document.getElementById('flash-messages');
    const flash = document.createElement('div');
    flash.className = `flash-message ${type}`;
    flash.innerHTML = `
        <div class="flash-message-title">${title}</div>
        <div class="flash-message-text">${message}</div>
    `;
    container.appendChild(flash);

    setTimeout(() => {
        flash.remove();
    }, 5000);
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleString();
}

function formatDateShort(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// ===== 3. API CALLS =====
async function apiCall(endpoint, options = {}) {
    // Authentication is handled via HTTP-only cookies
    // Cookies are automatically sent with fetch requests
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json'
        },
        credentials: 'same-origin'  // Ensure cookies are sent
    };

    try {
        const response = await fetch(endpoint, { ...defaultOptions, ...options });

        if (response.status === 401 || response.status === 403) {
            showFlashMessage('Access Denied', 'Your session has expired or you do not have admin access.', 'error');
            setTimeout(() => {
                window.location.href = '/auth';
            }, 2000);
            return null;
        }

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.error('API call failed:', error);
        showFlashMessage('Error', 'Failed to fetch data from server', 'error');
        return null;
    }
}

// ===== 4. DATA FETCHING FUNCTIONS =====
async function loadSecuritySummary() {
    const data = await apiCall('/api/v1/admin/security-summary');
    if (!data) return;

    // Update stat cards
    document.getElementById('stat-critical').textContent = data.incidents_by_severity.critical || 0;
    document.getElementById('stat-high').textContent = data.incidents_by_severity.high || 0;
    document.getElementById('stat-medium').textContent = data.incidents_by_severity.medium || 0;
    document.getElementById('stat-low').textContent = data.incidents_by_severity.low || 0;

    // Update recent activity
    document.getElementById('recent-incidents').textContent = data.recent_incidents_24h || 0;
    document.getElementById('recent-audits').textContent = data.recent_audit_logs_24h || 0;
    document.getElementById('failed-logins').textContent = data.failed_logins_24h || 0;

    // Update attack types
    const attackTypesList = document.getElementById('attack-types-list');
    if (data.top_attack_types && data.top_attack_types.length > 0) {
        attackTypesList.innerHTML = data.top_attack_types.map(item => `
            <div class="attack-type-item">
                <span class="attack-type-name">${escapeHtml(item.type)}</span>
                <span class="attack-type-count">${item.count}</span>
            </div>
        `).join('');
    } else {
        attackTypesList.innerHTML = '<div class="empty-state">No attack data available</div>';
    }

    // Update endpoints
    const endpointsList = document.getElementById('endpoints-list');
    if (data.top_targeted_endpoints && data.top_targeted_endpoints.length > 0) {
        endpointsList.innerHTML = data.top_targeted_endpoints.map(item => `
            <div class="endpoint-item">
                <span class="endpoint-path">${escapeHtml(item.endpoint)}</span>
                <span class="endpoint-count">${item.count}</span>
            </div>
        `).join('');
    } else {
        endpointsList.innerHTML = '<div class="empty-state">No endpoint data available</div>';
    }
}

async function loadSystemStats() {
    const data = await apiCall('/api/v1/admin/stats');
    if (!data) return;

    document.getElementById('total-users').textContent = data.total_users || 0;
    document.getElementById('active-sessions').textContent = data.active_sessions || 0;
    document.getElementById('active-users').textContent = data.active_users || 0;
}

async function loadSecurityIncidents() {
    const params = new URLSearchParams({
        limit: PAGE_SIZE,
        offset: state.incidentsPage * PAGE_SIZE
    });

    if (state.incidentsSeverity) params.append('severity', state.incidentsSeverity);
    if (state.incidentsType) params.append('incident_type', state.incidentsType);

    const data = await apiCall(`/api/v1/admin/security-incidents?${params}`);
    if (!data) return;

    const tbody = document.getElementById('incidents-table-body');

    if (!data.incidents || data.incidents.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center">No incidents found</td></tr>';
        return;
    }

    tbody.innerHTML = data.incidents.map(incident => `
        <tr>
            <td>${formatDateShort(incident.created_at)}</td>
            <td><span class="badge badge-${incident.severity}">${escapeHtml(incident.severity)}</span></td>
            <td>${escapeHtml(incident.incident_type)}</td>
            <td>${escapeHtml(incident.username || 'Anonymous')}</td>
            <td>${escapeHtml(incident.ip_address || 'N/A')}</td>
            <td>${escapeHtml(incident.endpoint || 'N/A')}</td>
            <td>${escapeHtml(incident.pattern_matched || 'N/A')}</td>
        </tr>
    `).join('');

    // Update pagination
    document.getElementById('incidents-page-info').textContent = `Page ${state.incidentsPage + 1}`;
    document.getElementById('incidents-prev').disabled = state.incidentsPage === 0;
    document.getElementById('incidents-next').disabled = data.incidents.length < PAGE_SIZE;
}

async function loadAuditLogs() {
    const params = new URLSearchParams({
        limit: PAGE_SIZE,
        offset: state.auditPage * PAGE_SIZE
    });

    if (state.auditAction) params.append('action', state.auditAction);

    const data = await apiCall(`/api/v1/admin/audit-logs?${params}`);
    if (!data) return;

    const tbody = document.getElementById('audit-table-body');

    if (!data.logs || data.logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center">No audit logs found</td></tr>';
        return;
    }

    tbody.innerHTML = data.logs.map(log => `
        <tr>
            <td>${formatDateShort(log.created_at)}</td>
            <td>${escapeHtml(log.username || 'System')}</td>
            <td>${escapeHtml(log.action)}</td>
            <td><span class="badge badge-${log.status}">${escapeHtml(log.status)}</span></td>
            <td>${escapeHtml(log.ip_address || 'N/A')}</td>
            <td>${log.details ? escapeHtml(JSON.stringify(log.details).substring(0, 50) + '...') : 'N/A'}</td>
        </tr>
    `).join('');

    // Update pagination
    document.getElementById('audit-page-info').textContent = `Page ${state.auditPage + 1}`;
    document.getElementById('audit-prev').disabled = state.auditPage === 0;
    document.getElementById('audit-next').disabled = data.logs.length < PAGE_SIZE;
}

async function loadUsers() {
    const params = new URLSearchParams({
        limit: PAGE_SIZE,
        offset: state.usersPage * PAGE_SIZE
    });

    if (state.userSearch) params.append('search', state.userSearch);

    const data = await apiCall(`/api/v1/admin/users?${params}`);
    if (!data) return;

    const tbody = document.getElementById('users-table-body');

    if (!data.users || data.users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center">No users found</td></tr>';
        return;
    }

    tbody.innerHTML = data.users.map(user => `
        <tr>
            <td>${user.id}</td>
            <td>${escapeHtml(user.username)}</td>
            <td>${escapeHtml(user.email)}</td>
            <td><span class="badge badge-${user.is_active ? 'active' : 'inactive'}">${user.account_status}</span></td>
            <td>${user.is_admin ? '<span class="badge badge-admin">Admin</span>' : ''}</td>
            <td>${formatDateShort(user.created_at)}</td>
            <td>${formatDateShort(user.last_login)}</td>
        </tr>
    `).join('');

    // Update pagination
    document.getElementById('users-page-info').textContent = `Page ${state.usersPage + 1}`;
    document.getElementById('users-prev').disabled = state.usersPage === 0;
    document.getElementById('users-next').disabled = data.users.length < PAGE_SIZE;
}

async function loadSessionStats() {
    const data = await apiCall('/api/v1/admin/sessions/stats');
    if (!data) return;

    document.getElementById('sessions-active').textContent = data.active_sessions || 0;
    document.getElementById('sessions-expired').textContent = data.expired_sessions || 0;
    document.getElementById('sessions-inactive').textContent = data.inactive_sessions || 0;
    document.getElementById('sessions-expiring').textContent = data.expiring_soon || 0;
}

async function cleanupSessions() {
    const data = await apiCall('/api/v1/admin/sessions/cleanup', { method: 'POST' });
    if (!data) return;

    showFlashMessage('Success', `Cleaned up ${data.sessions_deleted} expired sessions`, 'success');
    loadSessionStats();
}

// ===== 5. UTILITY FUNCTIONS =====
function escapeHtml(text) {
    if (!text) return '';
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.toString().replace(/[&<>"']/g, m => map[m]);
}

// ===== 6. PAGE NAVIGATION =====
function navigateToPage(pageId) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });

    // Remove active class from all nav items
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });

    // Show selected page
    document.getElementById(pageId).classList.add('active');

    // Add active class to clicked nav item
    document.querySelector(`[data-page="${pageId}"]`).classList.add('active');

    // Load data for the page
    state.currentPage = pageId;
    loadPageData(pageId);
}

function loadPageData(pageId) {
    switch (pageId) {
        case 'overview-page':
            loadSecuritySummary();
            loadSystemStats();
            break;
        case 'security-logs-page':
            loadSecurityIncidents();
            break;
        case 'audit-logs-page':
            loadAuditLogs();
            break;
        case 'users-page':
            loadUsers();
            break;
        case 'sessions-page':
            loadSessionStats();
            break;
    }
}

// ===== 7. EVENT LISTENERS =====
document.addEventListener('DOMContentLoaded', () => {
    // Navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const pageId = item.getAttribute('data-page');
            navigateToPage(pageId);
        });
    });

    // Theme is locked to dark mode
    document.documentElement.setAttribute('data-theme', 'dark');

    // Logout
    document.getElementById('logout-btn').addEventListener('click', () => {
        localStorage.removeItem('auth_token');
        window.location.href = '/auth';
    });

    // Security incidents filters
    document.getElementById('severity-filter').addEventListener('change', (e) => {
        state.incidentsSeverity = e.target.value;
        state.incidentsPage = 0;
        loadSecurityIncidents();
    });

    document.getElementById('incident-type-filter').addEventListener('change', (e) => {
        state.incidentsType = e.target.value;
        state.incidentsPage = 0;
        loadSecurityIncidents();
    });

    document.getElementById('refresh-incidents-btn').addEventListener('click', () => {
        loadSecurityIncidents();
    });

    // Incidents pagination
    document.getElementById('incidents-prev').addEventListener('click', () => {
        if (state.incidentsPage > 0) {
            state.incidentsPage--;
            loadSecurityIncidents();
        }
    });

    document.getElementById('incidents-next').addEventListener('click', () => {
        state.incidentsPage++;
        loadSecurityIncidents();
    });

    // Audit logs filters
    document.getElementById('action-filter').addEventListener('change', (e) => {
        state.auditAction = e.target.value;
        state.auditPage = 0;
        loadAuditLogs();
    });

    document.getElementById('refresh-audit-btn').addEventListener('click', () => {
        loadAuditLogs();
    });

    // Audit pagination
    document.getElementById('audit-prev').addEventListener('click', () => {
        if (state.auditPage > 0) {
            state.auditPage--;
            loadAuditLogs();
        }
    });

    document.getElementById('audit-next').addEventListener('click', () => {
        state.auditPage++;
        loadAuditLogs();
    });

    // Users search
    document.getElementById('user-search').addEventListener('input', (e) => {
        state.userSearch = e.target.value;
        state.usersPage = 0;
        // Debounce search
        clearTimeout(window.userSearchTimeout);
        window.userSearchTimeout = setTimeout(() => {
            loadUsers();
        }, 500);
    });

    document.getElementById('refresh-users-btn').addEventListener('click', () => {
        loadUsers();
    });

    // Users pagination
    document.getElementById('users-prev').addEventListener('click', () => {
        if (state.usersPage > 0) {
            state.usersPage--;
            loadUsers();
        }
    });

    document.getElementById('users-next').addEventListener('click', () => {
        state.usersPage++;
        loadUsers();
    });

    // Sessions
    document.getElementById('cleanup-sessions-btn').addEventListener('click', () => {
        if (confirm('Are you sure you want to cleanup all expired sessions?')) {
            cleanupSessions();
        }
    });

    document.getElementById('refresh-sessions-btn').addEventListener('click', () => {
        loadSessionStats();
    });

    // Sidebar toggle for mobile
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const sidebar = document.getElementById('sidebar');
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', () => {
            sidebar.classList.toggle('active');
        });
    }

    // Load initial data
    loadSecuritySummary();
    loadSystemStats();
});
