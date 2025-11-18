/**
 * Flowchart Dashboard Integration
 * Handles flowchart creation, editing, saving, and loading
 */

// State management (using window object for global access from AI planner)
window.currentFlowchart = window.currentFlowchart || null;
window.flowchartGenerator = window.flowchartGenerator || null;
window.nodeNotes = window.nodeNotes || {};  // Store notes for flowchart nodes
window.currentNodeId = null;  // Track which node is being edited
let allFlowcharts = [];

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Initialize only if we're on the flowchart page
    const flowchartPage = document.getElementById('flowchart-page');
    if (!flowchartPage) return;

    initializeFlowchartDashboard();
});

function initializeFlowchartDashboard() {
    console.log('Initializing Flowchart Dashboard');

    // Initialize flowchart generator
    window.flowchartGenerator = new FlowchartGenerator('flowchart-container');

    // Bind event listeners
    bindFlowchartEvents();

    // Load flowcharts when navigating to the page
    observePageNavigation();

    // Populate teams dropdown
    populateTeamsDropdown();
}

function bindFlowchartEvents() {
    // New flowchart button
    const newBtn = document.getElementById('new-flowchart-btn');
    if (newBtn) {
        newBtn.addEventListener('click', createNewFlowchart);
    }

    // List flowcharts button
    const listBtn = document.getElementById('flowchart-list-btn');
    if (listBtn) {
        listBtn.addEventListener('click', showFlowchartList);
    }

    // Back to list button
    const backBtn = document.getElementById('back-to-flowcharts');
    if (backBtn) {
        backBtn.addEventListener('click', showFlowchartList);
    }

    // Save flowchart button
    const saveBtn = document.getElementById('save-flowchart-btn');
    if (saveBtn) {
        saveBtn.addEventListener('click', saveFlowchart);
    }

    // Export flowchart button
    const exportBtn = document.getElementById('export-flowchart-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportFlowchart);
    }

    // Apply Mermaid code changes button
    const applyCodeBtn = document.getElementById('apply-mermaid-code-btn');
    if (applyCodeBtn) {
        applyCodeBtn.addEventListener('click', applyMermaidCodeChanges);
    }

    // Sync code editor when flowchart data changes
    syncCodeEditorWithFlowchart();

    // Template buttons
    const templateBtns = document.querySelectorAll('.template-item');
    templateBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const template = btn.dataset.template;
            // Create a new flowchart first if not already in editor
            if (!window.currentFlowchart) {
                createNewFlowchart();
            }
            // Load the selected template
            loadTemplate(template);
        });
    });
}

function observePageNavigation() {
    // Watch for navigation to flowchart page
    const navItems = document.querySelectorAll('.nav-item[data-page="flowchart-page"]');
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            setTimeout(() => {
                loadFlowcharts();
            }, 100);
        });
    });
}

async function createNewFlowchart() {
    window.currentFlowchart = {
        id: null,
        title: 'Untitled Flowchart',
        description: '',
        flowchart_data: '',
        template_name: null,
        status: 'draft',
        team_id: null,
        is_pinned: false
    };

    // Show editor view
    document.getElementById('flowchart-list-view').style.display = 'none';
    document.getElementById('flowchart-editor-view').style.display = 'block';

    // Reset inputs
    document.getElementById('flowchart-title-input').value = window.currentFlowchart.title;
    document.getElementById('flowchart-description').value = window.currentFlowchart.description;
    document.getElementById('flowchart-status').value = window.currentFlowchart.status;
    document.getElementById('flowchart-team').value = '';
    document.getElementById('flowchart-pinned').checked = false;

    // Clear canvas
    const container = document.getElementById('flowchart-container');
    container.innerHTML = '<div class="flowchart-placeholder">Select a template to get started</div>';
}

function showFlowchartList() {
    // Hide editor, show list
    document.getElementById('flowchart-editor-view').style.display = 'none';
    document.getElementById('flowchart-list-view').style.display = 'block';

    // Reload flowcharts
    loadFlowcharts();
}

function loadTemplate(templateName) {
    console.log('Loading template:', templateName);
    console.log('FlowchartGenerator available:', !!window.flowchartGenerator);
    console.log('Templates available:', window.flowchartGenerator ? Object.keys(window.flowchartGenerator.templates) : 'N/A');

    if (!window.flowchartGenerator) {
        console.error('FlowchartGenerator not initialized');
        showFlashMessage('Flowchart system not ready. Please refresh the page.', 'error');
        return;
    }

    if (templateName === 'blank') {
        // Load blank canvas
        const blankMermaid = 'flowchart TD\n    A[Start] --> B[End]';
        window.flowchartGenerator.render(blankMermaid).then(() => makeNodesClickable());
        if (window.currentFlowchart) {
            window.currentFlowchart.flowchart_data = blankMermaid;
            window.currentFlowchart.template_name = 'blank';
        }
        console.log('Blank template loaded successfully');
    } else if (window.flowchartGenerator.templates && window.flowchartGenerator.templates[templateName]) {
        // Load predefined template
        console.log('Rendering template:', templateName);
        window.flowchartGenerator.renderTemplate(templateName).then(() => makeNodesClickable());
        if (window.currentFlowchart) {
            window.currentFlowchart.flowchart_data = window.flowchartGenerator.templates[templateName];
            window.currentFlowchart.template_name = templateName;
        }
        console.log('Template loaded successfully');
    } else {
        console.error('Template not found:', templateName);
        console.error('Available templates:', window.flowchartGenerator.templates ? Object.keys(window.flowchartGenerator.templates) : 'none');
        showFlashMessage(`Template "${templateName}" not found`, 'error');
    }
}

async function saveFlowchart() {
    if (!window.currentFlowchart) {
        showFlashMessage('No flowchart to save', 'error');
        return;
    }

    // Get values from inputs
    window.currentFlowchart.title = document.getElementById('flowchart-title-input').value || 'Untitled Flowchart';
    window.currentFlowchart.description = document.getElementById('flowchart-description').value;
    window.currentFlowchart.status = document.getElementById('flowchart-status').value;

    // Convert team_id to integer or null
    const teamValue = document.getElementById('flowchart-team').value;
    window.currentFlowchart.team_id = teamValue ? parseInt(teamValue, 10) : null;

    window.currentFlowchart.is_pinned = document.getElementById('flowchart-pinned').checked;

    // Validate
    if (!window.currentFlowchart.flowchart_data) {
        showFlashMessage('Please create a flowchart first', 'error');
        return;
    }

    try {
        const url = window.currentFlowchart.id
            ? `/api/v1/flowcharts/${window.currentFlowchart.id}`
            : '/api/v1/flowcharts/create';

        const method = window.currentFlowchart.id ? 'PUT' : 'POST';

        // Get CSRF token from cookie
        const csrfToken = getCookie('csrf_token');

        const response = await fetch(url, {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken  // Include CSRF token
            },
            credentials: 'include',  // Include cookies in request
            body: JSON.stringify({
                title: window.currentFlowchart.title,
                description: window.currentFlowchart.description,
                flowchart_data: window.currentFlowchart.flowchart_data,
                flowchart_type: 'mermaid',
                template_name: window.currentFlowchart.template_name,
                status: window.currentFlowchart.status,
                team_id: window.currentFlowchart.team_id,
                is_pinned: window.currentFlowchart.is_pinned,
                node_notes: JSON.stringify(window.nodeNotes)  // Save interactive node notes
            })
        });

        console.log('Save response status:', response.status);

        if (response.ok) {
            const result = await response.json();
            window.currentFlowchart.id = result.flowchart_id || window.currentFlowchart.id;
            showFlashMessage(window.currentFlowchart.id ? 'Flowchart updated successfully!' : 'Flowchart saved successfully!', 'success');
        } else if (response.status === 401) {
            // Handle authentication error
            console.error('Authentication failed - session may have expired');
            showFlashMessage('Your session has expired. Please log in again.', 'error');
            setTimeout(() => {
                window.location.href = '/auth';
            }, 2000); // Give user time to see the message
        } else if (response.status === 422) {
            // Handle validation error
            try {
                const error = await response.json();
                console.error('Validation error:', error);
                console.error('Error details:', JSON.stringify(error, null, 2));

                // Show detailed validation errors
                if (error.detail && Array.isArray(error.detail)) {
                    console.error('Validation errors:', error.detail);
                    const fieldErrors = error.detail.map(err => `${err.loc.join('.')}: ${err.msg}`).join(', ');
                    showFlashMessage(`Validation failed: ${fieldErrors}`, 'error');
                } else if (error.details && Array.isArray(error.details)) {
                    console.error('Validation details:', error.details);
                    // Custom error format with 'field' instead of 'loc'
                    const fieldErrors = error.details.map(err => `${err.field}: ${err.message}`).join(', ');
                    showFlashMessage(`Validation failed: ${fieldErrors}`, 'error');
                } else {
                    showFlashMessage(error.detail || error.error || 'Validation failed', 'error');
                }
            } catch (parseError) {
                console.error('Failed to parse validation error:', parseError);
                showFlashMessage('Validation failed', 'error');
            }
        } else {
            // Handle other errors
            try {
                const error = await response.json();
                console.error('Save error:', error);
                showFlashMessage(error.detail || `Failed to save flowchart (${response.status})`, 'error');
            } catch (parseError) {
                console.error('Failed to parse error response:', parseError);
                showFlashMessage(`Failed to save flowchart (HTTP ${response.status})`, 'error');
            }
        }
    } catch (error) {
        console.error('Error saving flowchart:', error);
        showFlashMessage('An error occurred while saving: ' + error.message, 'error');
    }
}

async function loadFlowcharts() {
    try {
        console.log('Loading flowcharts...');
        const response = await fetch('/api/v1/flowcharts', {
            credentials: 'include'  // Include cookies in request
        });

        console.log('Flowcharts response status:', response.status);

        if (response.ok) {
            allFlowcharts = await response.json();
            console.log('Loaded flowcharts:', allFlowcharts);
            console.log('Number of flowcharts:', allFlowcharts.length);
            renderFlowchartGrid(allFlowcharts);
        } else {
            console.error('Failed to load flowcharts, status:', response.status);
        }
    } catch (error) {
        console.error('Error loading flowcharts:', error);
    }
}

function renderFlowchartGrid(flowcharts) {
    console.log('Rendering flowchart grid with:', flowcharts);
    const grid = document.getElementById('flowchart-grid');
    if (!grid) {
        console.error('flowchart-grid element not found!');
        return;
    }

    console.log('Grid element found:', grid);

    if (!flowcharts || flowcharts.length === 0) {
        console.log('No flowcharts to display');
        grid.innerHTML = `
            <div class="flowchart-empty-state">
                <svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24" fill="none"
                    stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M21 16V8a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2z"></path>
                    <polyline points="7 10 12 15 17 10"></polyline>
                </svg>
                <h3>No flowcharts yet</h3>
                <p>Create your first flowchart to visualize workflows and processes</p>
                <button class="btn btn-primary" onclick="document.getElementById('new-flowchart-btn').click()">
                    Create Flowchart
                </button>
            </div>
        `;
        return;
    }

    grid.innerHTML = flowcharts.map(flowchart => `
        <div class="flowchart-card" data-id="${flowchart.id}">
            <div class="flowchart-card-header">
                <h4>${escapeHtml(flowchart.title)}</h4>
                ${flowchart.is_pinned ? '<span class="pin-badge">📌</span>' : ''}
            </div>
            <div class="flowchart-card-meta">
                <span class="status-badge status-${flowchart.status}">${flowchart.status}</span>
                <span class="date">${formatDate(flowchart.created_at)}</span>
            </div>
            ${flowchart.description ? `<p class="flowchart-description">${escapeHtml(flowchart.description)}</p>` : ''}
            <div class="flowchart-card-actions">
                <button class="btn-icon" onclick="openFlowchart(${flowchart.id})" title="Open">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none"
                        stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                        <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                    </svg>
                </button>
                <button class="btn-icon" onclick="deleteFlowchart(${flowchart.id})" title="Delete">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none"
                        stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="3 6 5 6 21 6"></polyline>
                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                    </svg>
                </button>
            </div>
        </div>
    `).join('');
}

async function openFlowchart(id) {
    try {
        const response = await fetch(`/api/v1/flowcharts/${id}`, {
            credentials: 'include'  // Include cookies in request
        });

        if (response.ok) {
            const flowchart = await response.json();
            window.currentFlowchart = flowchart;

            // Show editor
            document.getElementById('flowchart-list-view').style.display = 'none';
            document.getElementById('flowchart-editor-view').style.display = 'block';

            // Populate fields
            document.getElementById('flowchart-title-input').value = flowchart.title;
            document.getElementById('flowchart-description').value = flowchart.description || '';
            document.getElementById('flowchart-status').value = flowchart.status;
            document.getElementById('flowchart-team').value = flowchart.team_id || '';
            document.getElementById('flowchart-pinned').checked = flowchart.is_pinned;

            // Populate code editor with Mermaid code
            const codeEditor = document.getElementById('flowchart-code-editor');
            if (codeEditor) {
                codeEditor.value = flowchart.flowchart_data || '';
            }

            // Load node notes from database
            if (flowchart.node_notes) {
                try {
                    window.nodeNotes = JSON.parse(flowchart.node_notes);
                } catch (e) {
                    console.error('Failed to parse node_notes:', e);
                    window.nodeNotes = {};
                }
            } else {
                window.nodeNotes = {};
            }

            // Render flowchart
            if (flowchart.flowchart_data) {
                window.flowchartGenerator.render(flowchart.flowchart_data).then(() => makeNodesClickable());
            }
        } else {
            showFlashMessage('Failed to load flowchart', 'error');
        }
    } catch (error) {
        console.error('Error opening flowchart:', error);
        showFlashMessage('An error occurred', 'error');
    }
}

async function deleteFlowchart(id) {
    if (!confirm('Are you sure you want to delete this flowchart?')) {
        return;
    }

    try {
        // Get CSRF token from cookie
        const csrfToken = getCookie('csrf_token');

        const response = await fetch(`/api/v1/flowcharts/${id}`, {
            method: 'DELETE',
            headers: {
                'X-CSRF-Token': csrfToken  // Include CSRF token
            },
            credentials: 'include'  // Include cookies in request
        });

        if (response.ok) {
            showFlashMessage('Flowchart deleted successfully', 'success');
            loadFlowcharts();
        } else {
            showFlashMessage('Failed to delete flowchart', 'error');
        }
    } catch (error) {
        console.error('Error deleting flowchart:', error);
        showFlashMessage('An error occurred', 'error');
    }
}

async function exportFlowchart() {
    if (!window.flowchartGenerator) {
        showFlashMessage('No flowchart to export', 'error');
        return;
    }

    try {
        const filename = (window.currentFlowchart?.title || 'flowchart').replace(/[^a-z0-9]/gi, '_').toLowerCase();
        await window.flowchartGenerator.download(filename, 'png');
        showFlashMessage('Flowchart exported successfully!', 'success');
    } catch (error) {
        console.error('Export error:', error);
        showFlashMessage('Failed to export flowchart', 'error');
    }
}

// Populate teams dropdown
async function populateTeamsDropdown() {
    const teamSelect = document.getElementById('flowchart-team');
    if (!teamSelect) return;

    try {
        const response = await fetch('/api/v1/drive/teams', {
            credentials: 'include'
        });

        if (response.ok) {
            const data = await response.json();
            console.log('Loaded teams for dropdown:', data);

            // Extract teams array from response
            const teams = data.teams || data || [];

            // Clear existing options except "Personal"
            teamSelect.innerHTML = '<option value="">Personal</option>';

            // Add team options
            teams.forEach(team => {
                const option = document.createElement('option');
                option.value = team.id;
                option.textContent = team.name;
                teamSelect.appendChild(option);
            });

            console.log('Teams dropdown populated with', teams.length, 'teams');
        } else {
            console.error('Failed to load teams for dropdown');
        }
    } catch (error) {
        console.error('Error loading teams for dropdown:', error);
    }
}

// Extract stable node name from Mermaid-generated ID
// Mermaid generates IDs like "flowchart-A-0", "flowchart-A-23", etc.
// We need the stable part (e.g., "A") for note storage
function extractStableNodeId(mermaidId) {
    if (!mermaidId) return null;

    // Pattern: flowchart-{NODE_NAME}-{UNIQUE_NUMBER}
    // We want just the NODE_NAME part
    const match = mermaidId.match(/flowchart-([A-Za-z0-9]+)-\d+/);
    if (match) {
        return match[1]; // Return just the node name (e.g., "A", "B", "StoryCreation")
    }

    // Fallback: if pattern doesn't match, return the full ID
    return mermaidId;
}

// Node Notes Functions
function makeNodesClickable() {
    // Wait a bit for Mermaid to finish rendering
    setTimeout(() => {
        const svg = document.querySelector('#flowchart-container svg');
        if (!svg) {
            console.log('No SVG found in flowchart container');
            return;
        }

        console.log('Making nodes clickable...');

        // Mermaid uses different selectors - try multiple approaches
        // Find all g elements that contain rectangles (nodes)
        const nodeGroups = svg.querySelectorAll('g.node, g[class*="flowchart"]');

        console.log('Found', nodeGroups.length, 'potential node groups');

        nodeGroups.forEach((nodeGroup, index) => {
            // Get node ID - Mermaid uses id attribute on the g element
            let mermaidId = nodeGroup.id;

            // If no id, try to extract from class
            if (!mermaidId) {
                const classMatch = nodeGroup.className.baseVal.match(/flowchart-(\w+)/);
                mermaidId = classMatch ? classMatch[1] : `node-${index}`;
            }

            // Extract stable node ID (without the changing number)
            const stableNodeId = extractStableNodeId(mermaidId);

            // Get the node label text
            const labelElement = nodeGroup.querySelector('text, span, foreignObject');
            const nodeLabel = labelElement ? labelElement.textContent.trim() : stableNodeId;

            console.log('Processing node:', mermaidId, '→ Stable ID:', stableNodeId, 'Label:', nodeLabel);

            // Make entire node group clickable
            nodeGroup.style.cursor = 'pointer';
            nodeGroup.style.pointerEvents = 'all';

            // Remove any existing click handlers
            const newNode = nodeGroup.cloneNode(true);
            nodeGroup.parentNode.replaceChild(newNode, nodeGroup);

            // Add click event to new node (use stable ID)
            newNode.addEventListener('click', (e) => {
                e.stopPropagation();
                e.preventDefault();
                console.log('Node clicked:', mermaidId, '→ Stable ID:', stableNodeId);
                openNodeNotesModal(stableNodeId, newNode, nodeLabel);
            });

            // Add note badge if this node has notes (use stable ID)
            if (window.nodeNotes[stableNodeId]) {
                addNoteBadge(newNode, stableNodeId);
            }
        });

        console.log('Nodes are now clickable!');
    }, 800);
}

function openNodeNotesModal(nodeId, nodeElement, nodeLabel) {
    window.currentNodeId = nodeId;

    console.log('Opening notes modal for node:', nodeId, 'Label:', nodeLabel);
    console.log('window.nodeNotes contains:', Object.keys(window.nodeNotes).length, 'notes');
    console.log('Full window.nodeNotes:', JSON.stringify(window.nodeNotes));

    // Use provided label or extract it
    if (!nodeLabel && nodeElement) {
        const labelElement = nodeElement.querySelector('text, span, foreignObject');
        nodeLabel = labelElement ? labelElement.textContent.trim() : nodeId;
    }

    // Update modal title and node name
    document.getElementById('node-notes-node-name').textContent = nodeLabel || nodeId;

    // Load existing note if any
    const existingNote = window.nodeNotes[nodeId] || '';
    const textarea = document.getElementById('node-notes-textarea');
    if (textarea) {
        textarea.value = existingNote;
        console.log('Loaded note into textarea:', existingNote.substring(0, 50) + (existingNote.length > 50 ? '...' : ''));
    } else {
        console.error('Textarea not found!');
    }

    // Show modal overlay and modal with active class (required by CSS)
    const overlay = document.getElementById('node-notes-modal-overlay');
    const modal = document.getElementById('node-notes-modal');

    if (overlay && modal) {
        overlay.style.display = 'grid';
        overlay.classList.add('active');
        modal.style.display = 'flex';
        modal.classList.add('active');
        console.log('Modal displayed successfully');
    } else {
        console.error('Modal or overlay not found!', { overlay: !!overlay, modal: !!modal });
    }
}

function closeNodeNotesModal() {
    const overlay = document.getElementById('node-notes-modal-overlay');
    const modal = document.getElementById('node-notes-modal');

    if (overlay) {
        overlay.style.display = 'none';
        overlay.classList.remove('active');
    }

    if (modal) {
        modal.style.display = 'none';
        modal.classList.remove('active');
    }

    window.currentNodeId = null;
}

function saveNodeNote() {
    if (!window.currentNodeId) return;

    const noteText = document.getElementById('node-notes-textarea').value.trim();

    // Save or delete note
    if (noteText) {
        window.nodeNotes[window.currentNodeId] = noteText;
    } else {
        delete window.nodeNotes[window.currentNodeId];
    }

    // Update currentFlowchart
    if (window.currentFlowchart) {
        window.currentFlowchart.node_notes = JSON.stringify(window.nodeNotes);
    }

    console.log('Note saved for node:', window.currentNodeId);
    console.log('window.nodeNotes after save:', JSON.stringify(window.nodeNotes));

    // Close modal
    closeNodeNotesModal();

    // IMPORTANT: Preserve notes before re-rendering
    const preservedNotes = {...window.nodeNotes};

    // Re-render to show/hide badges
    if (window.currentFlowchart && window.currentFlowchart.flowchart_data) {
        window.flowchartGenerator.render(window.currentFlowchart.flowchart_data)
            .then(() => {
                // Restore notes after render (in case they got cleared)
                window.nodeNotes = preservedNotes;
                makeNodesClickable();
                showFlashMessage('Note saved! Remember to save the flowchart.', 'success');
            });
    }
}

function addNoteBadge(nodeElement, nodeId) {
    // Check if badge already exists
    if (nodeElement.querySelector('.note-badge')) return;

    // Get the bounding box of the node to position the badge
    const bbox = nodeElement.getBBox();

    // Create badge group
    const badge = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    badge.classList.add('note-badge');
    // Position in top-right corner of the node
    badge.setAttribute('transform', `translate(${bbox.x + bbox.width + 5}, ${bbox.y - 5})`);
    badge.style.cursor = 'pointer';

    // Badge background circle
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('r', '12');
    circle.setAttribute('fill', '#a78bfa');
    circle.setAttribute('stroke', '#ffffff');
    circle.setAttribute('stroke-width', '2');
    circle.setAttribute('cx', '0');
    circle.setAttribute('cy', '0');

    // Badge text (note emoji or icon)
    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', '0');
    text.setAttribute('y', '1');
    text.setAttribute('text-anchor', 'middle');
    text.setAttribute('dominant-baseline', 'central');
    text.setAttribute('fill', '#ffffff');
    text.setAttribute('font-size', '14');
    text.setAttribute('font-weight', 'bold');
    text.textContent = '📝';

    badge.appendChild(circle);
    badge.appendChild(text);

    // Add click handler to badge (same as node)
    badge.addEventListener('click', (e) => {
        e.stopPropagation();
        e.preventDefault();
        console.log('Badge clicked for node:', nodeId);
        const labelElement = nodeElement.querySelector('text, span, foreignObject');
        const nodeLabel = labelElement ? labelElement.textContent.trim() : nodeId;
        openNodeNotesModal(nodeId, nodeElement, nodeLabel);
    });

    nodeElement.appendChild(badge);
    console.log('Badge added to node:', nodeId);
}

// Export functions for use in HTML onclick handlers
window.openNodeNotesModal = openNodeNotesModal;
window.closeNodeNotesModal = closeNodeNotesModal;
window.saveNodeNote = saveNodeNote;

// Code editor functions
function syncCodeEditorWithFlowchart() {
    const codeEditor = document.getElementById('flowchart-code-editor');
    if (!codeEditor) return;

    // Update code editor when flowchart data changes
    if (window.currentFlowchart && window.currentFlowchart.flowchart_data) {
        codeEditor.value = window.currentFlowchart.flowchart_data;
    } else {
        codeEditor.value = '';
    }
}

async function applyMermaidCodeChanges() {
    const codeEditor = document.getElementById('flowchart-code-editor');
    if (!codeEditor) return;

    const mermaidCode = codeEditor.value.trim();

    if (!mermaidCode) {
        showFlashMessage('Please enter Mermaid code', 'error');
        return;
    }

    // Update current flowchart data
    if (!window.currentFlowchart) {
        window.currentFlowchart = {
            id: null,
            title: 'Untitled Flowchart',
            description: '',
            flowchart_data: '',
            template_name: null,
            status: 'draft',
            team_id: null,
            is_pinned: false
        };
    }

    window.currentFlowchart.flowchart_data = mermaidCode;

    // Preserve notes before re-rendering
    const preservedNotes = {...window.nodeNotes};

    // Re-render the flowchart
    try {
        if (!window.flowchartGenerator) {
            console.log('Initializing FlowchartGenerator...');
            window.flowchartGenerator = new FlowchartGenerator('flowchart-container');
            await new Promise(resolve => setTimeout(resolve, 500));
        }

        await window.flowchartGenerator.render(mermaidCode);

        // Restore notes and make nodes clickable
        window.nodeNotes = preservedNotes;
        makeNodesClickable();

        showFlashMessage('Flowchart updated! Remember to save your changes.', 'success');
    } catch (error) {
        console.error('Error rendering flowchart:', error);
        showFlashMessage('Failed to render flowchart. Please check your Mermaid syntax.', 'error');
    }
}

// Utility functions
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatDate(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diffTime = Math.abs(now - date);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    if (diffDays === 0) return 'Today';
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays} days ago`;
    return date.toLocaleDateString();
}

function showFlashMessage(message, type = 'info') {
    // Use existing flash message system from user-dashboard.js
    if (typeof window.showFlash === 'function') {
        window.showFlash(message, type);
    } else {
        // Fallback to alert if main flash system not loaded
        alert(message);
    }
}

// Export functions for use in HTML onclick handlers
window.openFlowchart = openFlowchart;
window.deleteFlowchart = deleteFlowchart;
