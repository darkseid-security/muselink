/**
 * AI-Powered Planner
 * Gemini integration for intelligent workflow creation and optimization
 */

class AIPlanner {
    constructor() {
        this.currentWorkflow = null;
        this.mermaidCode = null;
        this.init();
    }

    init() {
        // Tab switching
        document.querySelectorAll('.ai-panel-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                this.switchTab(tab.dataset.tab);
            });
        });

        // AI Generate Workflow
        const generateBtn = document.getElementById('ai-generate-workflow-btn');
        if (generateBtn) {
            generateBtn.addEventListener('click', () => this.generateWorkflow());
        }

        // Get Suggestions
        const suggestionsBtn = document.getElementById('ai-get-suggestions-btn');
        if (suggestionsBtn) {
            suggestionsBtn.addEventListener('click', () => this.getSuggestions());
        }

        // Optimize Workflow
        const optimizeBtn = document.getElementById('ai-optimize-workflow-btn');
        if (optimizeBtn) {
            optimizeBtn.addEventListener('click', () => this.optimizeWorkflow());
        }

        // Quick Actions
        document.getElementById('ai-improve-current')?.addEventListener('click', () => {
            this.improveCurrent();
        });

        document.getElementById('ai-from-idea')?.addEventListener('click', () => {
            this.generateFromIdea();
        });

        document.getElementById('ai-add-checkpoint')?.addEventListener('click', () => {
            this.addCheckpoints();
        });
    }

    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.ai-panel-tab').forEach(tab => {
            tab.classList.toggle('active', tab.dataset.tab === tabName);
        });

        // Update tab content
        document.querySelectorAll('.ai-panel-content').forEach(content => {
            content.classList.remove('active');
        });

        const targetPanel = document.getElementById(`ai-${tabName}-panel`);
        if (targetPanel) {
            targetPanel.classList.add('active');
        }
    }

    async generateWorkflow() {
        const description = document.getElementById('ai-workflow-description').value.trim();
        const statusEl = document.getElementById('ai-generate-status');
        const btn = document.getElementById('ai-generate-workflow-btn');

        if (!description) {
            this.showStatus('Please describe your workflow first.', 'error');
            return;
        }

        // Set loading state
        btn.disabled = true;
        btn.innerHTML = `
            <div class="ai-loading" style="display: inline-flex; gap: 4px; margin-right: 6px;">
                <span style="width: 4px; height: 4px; border-radius: 50%; background: white; animation: bounce 1.4s infinite;"></span>
                <span style="width: 4px; height: 4px; border-radius: 50%; background: white; animation: bounce 1.4s infinite; animation-delay: 0.2s;"></span>
                <span style="width: 4px; height: 4px; border-radius: 50%; background: white; animation: bounce 1.4s infinite; animation-delay: 0.4s;"></span>
            </div>
            Generating...
        `;
        statusEl.textContent = 'AI is creating your workflow...';
        statusEl.style.color = '#a78bfa';

        try {
            const token = this.getAuthToken();
            const csrfToken = this.getCSRFToken();
            const response = await fetch('/api/v1/gemini/generate-flowchart', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`,
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({
                    description: description
                })
            });

            const data = await response.json();

            if (data.success) {
                this.mermaidCode = data.mermaid;
                this.currentWorkflow = description;

                // Render the flowchart using the existing system
                await this.renderFlowchart(data.mermaid);

                // Create a flowchart entry that can be saved
                this.createFlowchartEntry(description, data.mermaid);

                statusEl.textContent = '✓ Workflow generated! Now you can save it using the "Save Flowchart" button.';
                statusEl.style.color = '#86efac';

                // Clear status after 5 seconds
                setTimeout(() => {
                    statusEl.textContent = '';
                }, 5000);
            } else {
                statusEl.textContent = '✗ ' + (data.error || 'Failed to generate workflow');
                statusEl.style.color = '#fca5a5';
            }
        } catch (error) {
            console.error('Workflow generation error:', error);
            statusEl.textContent = '✗ Failed to generate workflow. Please try again.';
            statusEl.style.color = '#fca5a5';
        } finally {
            // Reset button
            btn.disabled = false;
            btn.innerHTML = `
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align: middle; margin-right: 6px;">
                    <circle cx="12" cy="12" r="10"></circle>
                    <path d="M12 16v-4"></path>
                    <path d="M12 8h.01"></path>
                </svg>
                Generate Workflow
            `;
        }
    }

    async getSuggestions() {
        const listEl = document.getElementById('ai-suggestions-list');
        const btn = document.getElementById('ai-get-suggestions-btn');

        if (!this.currentWorkflow) {
            listEl.innerHTML = '<p style="color: #fca5a5; font-size: 12px;">Please generate a workflow first.</p>';
            return;
        }

        // Set loading state
        btn.disabled = true;
        btn.innerHTML = `
            <div class="ai-loading" style="display: inline-flex; gap: 4px; margin-right: 6px;">
                <span style="width: 4px; height: 4px; border-radius: 50%; background: currentColor; animation: bounce 1.4s infinite;"></span>
                <span style="width: 4px; height: 4px; border-radius: 50%; background: currentColor; animation: bounce 1.4s infinite; animation-delay: 0.2s;"></span>
                <span style="width: 4px; height: 4px; border-radius: 50%; background: currentColor; animation: bounce 1.4s infinite; animation-delay: 0.4s;"></span>
            </div>
            Analyzing...
        `;
        listEl.innerHTML = '<p style="color: #a78bfa; font-size: 12px;">AI is analyzing your workflow...</p>';

        try {
            const token = this.getAuthToken();
            const csrfToken = this.getCSRFToken();
            const response = await fetch('/api/v1/gemini/suggest-next-steps', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`,
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({
                    description: this.currentWorkflow
                })
            });

            const data = await response.json();

            if (data.success && data.suggestions && data.suggestions.length > 0) {
                this.displaySuggestions(data.suggestions);
            } else {
                listEl.innerHTML = '<p style="color: #8b7fa8; font-size: 12px;">No suggestions available.</p>';
            }
        } catch (error) {
            console.error('Suggestions error:', error);
            listEl.innerHTML = '<p style="color: #fca5a5; font-size: 12px;">Failed to get suggestions. Please try again.</p>';
        } finally {
            // Reset button
            btn.disabled = false;
            btn.innerHTML = `
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align: middle; margin-right: 6px;">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                    <polyline points="17 8 12 3 7 8"></polyline>
                    <line x1="12" y1="3" x2="12" y2="15"></line>
                </svg>
                Get AI Suggestions
            `;
        }
    }

    async optimizeWorkflow() {
        const resultsEl = document.getElementById('ai-optimization-results');
        const btn = document.getElementById('ai-optimize-workflow-btn');

        if (!this.currentWorkflow) {
            resultsEl.innerHTML = '<p style="color: #fca5a5; font-size: 12px;">Please generate a workflow first.</p>';
            return;
        }

        // Set loading state
        btn.disabled = true;
        btn.innerHTML = `
            <div class="ai-loading" style="display: inline-flex; gap: 4px; margin-right: 6px;">
                <span style="width: 4px; height: 4px; border-radius: 50%; background: currentColor; animation: bounce 1.4s infinite;"></span>
                <span style="width: 4px; height: 4px; border-radius: 50%; background: currentColor; animation: bounce 1.4s infinite; animation-delay: 0.2s;"></span>
                <span style="width: 4px; height: 4px; border-radius: 50%; background: currentColor; animation: bounce 1.4s infinite; animation-delay: 0.4s;"></span>
            </div>
            Optimizing...
        `;
        resultsEl.innerHTML = '<p style="color: #a78bfa; font-size: 12px;">AI is analyzing and optimizing your workflow...</p>';

        try {
            const token = this.getAuthToken();
            const csrfToken = this.getCSRFToken();
            const response = await fetch('/api/v1/gemini/optimize-workflow', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`,
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({
                    description: this.currentWorkflow
                })
            });

            const data = await response.json();

            if (data.success && data.analysis) {
                this.displayOptimization(data.analysis);
            } else {
                resultsEl.innerHTML = '<p style="color: #fca5a5; font-size: 12px;">Optimization failed. Please try again.</p>';
            }
        } catch (error) {
            console.error('Optimization error:', error);
            resultsEl.innerHTML = '<p style="color: #fca5a5; font-size: 12px;">Failed to optimize workflow. Please try again.</p>';
        } finally {
            // Reset button
            btn.disabled = false;
            btn.innerHTML = `
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align: middle; margin-right: 6px;">
                    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
                </svg>
                Optimize Workflow
            `;
        }
    }

    displaySuggestions(suggestions) {
        const listEl = document.getElementById('ai-suggestions-list');
        let html = '';

        suggestions.forEach(sugg => {
            html += `
                <div class="suggestion-item">
                    <div class="suggestion-header">
                        <span class="suggestion-title">${this.escapeHtml(sugg.title)}</span>
                        <span class="suggestion-type ${sugg.type}">${sugg.type}</span>
                    </div>
                    <div class="suggestion-description">${this.escapeHtml(sugg.description)}</div>
                    ${sugg.placement ? `<div class="suggestion-placement">Place: ${this.escapeHtml(sugg.placement)}</div>` : ''}
                </div>
            `;
        });

        listEl.innerHTML = html;
    }

    displayOptimization(analysis) {
        const resultsEl = document.getElementById('ai-optimization-results');
        let html = '';

        // Efficiency Score
        if (analysis.efficiency_score) {
            html += `
                <div class="efficiency-score">
                    <span class="efficiency-score-label">Efficiency Score:</span>
                    <span class="efficiency-score-value">${analysis.efficiency_score}/10</span>
                </div>
            `;
        }

        // Time Estimate
        if (analysis.time_estimate) {
            html += `<p style="color: #a78bfa; font-size: 12px; margin-top: 12px;">Estimated Duration: ${this.escapeHtml(analysis.time_estimate)}</p>`;
        }

        // Bottlenecks
        if (analysis.bottlenecks && analysis.bottlenecks.length > 0) {
            html += `
                <div class="optimization-section">
                    <h4>
                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="12" y1="8" x2="12" y2="12"></line>
                            <line x1="12" y1="16" x2="12.01" y2="16"></line>
                        </svg>
                        Bottlenecks Found
                    </h4>
                    <ul>
                        ${analysis.bottlenecks.map(b => `<li><strong>${this.escapeHtml(b.step)}:</strong> ${this.escapeHtml(b.solution)}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        // Parallelization Opportunities
        if (analysis.parallelization && analysis.parallelization.length > 0) {
            html += `
                <div class="optimization-section">
                    <h4>
                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="17 1 21 5 17 9"></polyline>
                            <path d="M3 11V9a4 4 0 0 1 4-4h14"></path>
                            <polyline points="7 23 3 19 7 15"></polyline>
                            <path d="M21 13v2a4 4 0 0 1-4 4H3"></path>
                        </svg>
                        Parallelization Opportunities
                    </h4>
                    <ul>
                        ${analysis.parallelization.map(p => `<li>${p.steps.join(', ')} - ${this.escapeHtml(p.reason)}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        // Missing Steps
        if (analysis.missing_steps && analysis.missing_steps.length > 0) {
            html += `
                <div class="optimization-section">
                    <h4>
                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="12" y1="8" x2="12" y2="16"></line>
                            <line x1="8" y1="12" x2="16" y2="12"></line>
                        </svg>
                        Recommended Additions
                    </h4>
                    <ul>
                        ${analysis.missing_steps.map(m => `<li><strong>${this.escapeHtml(m.suggestion)}</strong> (after ${this.escapeHtml(m.after)})</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        // Improvements
        if (analysis.improvements && analysis.improvements.length > 0) {
            html += `
                <div class="optimization-section">
                    <h4>
                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
                        </svg>
                        Improvement Suggestions
                    </h4>
                    <ul>
                        ${analysis.improvements.map(i => `<li><span class="priority-badge priority-${i.priority}">${i.priority.toUpperCase()}</span> ${this.escapeHtml(i.suggestion)}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        resultsEl.innerHTML = html || '<p style="color: #8b7fa8; font-size: 12px;">No optimization suggestions available.</p>';
    }

    async renderFlowchart(mermaidCode) {
        // Use the existing FlowchartGenerator system
        if (!window.flowchartGenerator) {
            console.log('Initializing FlowchartGenerator for AI-generated flowchart...');
            window.flowchartGenerator = new FlowchartGenerator('flowchart-container');

            // Wait for Mermaid.js to load
            await new Promise(resolve => setTimeout(resolve, 1000));
        }

        try {
            // Use the existing render method which handles all edge cases
            await window.flowchartGenerator.render(mermaidCode);
            console.log('AI-generated flowchart rendered successfully');

            // Make nodes clickable for interactive notes
            if (typeof makeNodesClickable === 'function') {
                makeNodesClickable();
            }
        } catch (error) {
            console.error('Error rendering AI-generated flowchart:', error);
            const container = document.getElementById('flowchart-container');
            if (container) {
                container.innerHTML = `
                    <div style="padding: 20px; text-align: center; color: #fca5a5;">
                        <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-bottom: 12px;">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="12" y1="8" x2="12" y2="12"></line>
                            <line x1="12" y1="16" x2="12.01" y2="16"></line>
                        </svg>
                        <p>Failed to render flowchart</p>
                        <small style="color: #a78bfa;">${this.escapeHtml(error.message)}</small>
                    </div>
                `;
            }
        }
    }

    createFlowchartEntry(description, mermaidCode) {
        // Show editor view instead of list view
        const listView = document.getElementById('flowchart-list-view');
        const editorView = document.getElementById('flowchart-editor-view');

        if (listView) listView.style.display = 'none';
        if (editorView) editorView.style.display = 'block';

        // Preserve existing notes when creating new flowchart
        const existingNotes = window.nodeNotes || {};

        // Create a new flowchart entry or update existing one
        if (!window.currentFlowchart || !window.currentFlowchart.id) {
            // New AI-generated flowchart
            window.currentFlowchart = {
                id: null,
                title: `AI: ${description.substring(0, 40)}${description.length > 40 ? '...' : ''}`,
                description: description,
                flowchart_data: mermaidCode,
                template_name: 'ai_generated',
                status: 'draft',
                team_id: null,
                is_pinned: false,
                node_notes: JSON.stringify(existingNotes)  // Initialize node_notes
            };

            // Reset notes for new flowchart (user can add new ones)
            window.nodeNotes = {};
        } else {
            // Update existing flowchart with AI-generated data
            window.currentFlowchart.flowchart_data = mermaidCode;
            if (!window.currentFlowchart.description) {
                window.currentFlowchart.description = description;
            }
            // Preserve existing notes
            if (!window.currentFlowchart.node_notes) {
                window.currentFlowchart.node_notes = JSON.stringify(existingNotes);
            }
        }

        // Update form fields to reflect the flowchart data
        const titleInput = document.getElementById('flowchart-title-input');
        const descInput = document.getElementById('flowchart-description');
        const statusSelect = document.getElementById('flowchart-status');

        if (titleInput) titleInput.value = window.currentFlowchart.title;
        if (descInput) descInput.value = window.currentFlowchart.description;
        if (statusSelect) statusSelect.value = window.currentFlowchart.status;

        // Sync the code editor with the generated flowchart
        const codeEditor = document.getElementById('flowchart-code-editor');
        if (codeEditor && window.currentFlowchart.flowchart_data) {
            codeEditor.value = window.currentFlowchart.flowchart_data;
        }

        // Highlight the save button to draw attention
        this.highlightSaveButton();

        console.log('Flowchart entry created and ready to save:', window.currentFlowchart.title);
    }

    highlightSaveButton() {
        const saveBtn = document.getElementById('save-flowchart-btn');
        if (!saveBtn) return;

        // Add a pulsing animation class
        saveBtn.style.animation = 'pulse 2s ease-in-out infinite';
        saveBtn.style.boxShadow = '0 0 0 0 rgba(102, 126, 234, 0.7)';

        // Add pulse keyframes if not already added
        if (!document.getElementById('ai-pulse-animation')) {
            const style = document.createElement('style');
            style.id = 'ai-pulse-animation';
            style.textContent = `
                @keyframes pulse {
                    0% {
                        box-shadow: 0 0 0 0 rgba(102, 126, 234, 0.7);
                    }
                    50% {
                        box-shadow: 0 0 0 10px rgba(102, 126, 234, 0);
                    }
                    100% {
                        box-shadow: 0 0 0 0 rgba(102, 126, 234, 0);
                    }
                }
            `;
            document.head.appendChild(style);
        }

        // Remove animation after user clicks save or after 10 seconds
        const removePulse = () => {
            saveBtn.style.animation = '';
            saveBtn.style.boxShadow = '';
            saveBtn.removeEventListener('click', removePulse);
        };

        saveBtn.addEventListener('click', removePulse);
        setTimeout(removePulse, 10000);
    }

    async improveCurrent() {
        if (!this.currentWorkflow && !this.mermaidCode) {
            alert('Please generate a workflow first before improving it.');
            return;
        }

        // If we have a flowchart, generate an improved version
        if (this.mermaidCode) {
            const improvePrompt = `Improve this workflow by adding quality checkpoints, error handling, and optimization steps:\n\n${this.currentWorkflow}`;
            document.getElementById('ai-workflow-description').value = improvePrompt;

            // Switch to generator tab
            this.switchTab('generator');

            // Auto-generate the improved workflow
            await this.generateWorkflow();
        } else {
            // If no flowchart yet, just show optimization
            this.switchTab('optimizer');
            await this.optimizeWorkflow();
        }
    }

    async generateFromIdea() {
        // TODO: Implement idea selection modal
        alert('This will allow you to select an existing idea and generate a workflow from it. Coming soon!');
    }

    async addCheckpoints() {
        const description = this.currentWorkflow || 'current workflow';
        document.getElementById('ai-workflow-description').value = `Add quality checkpoints to this workflow: ${description}`;

        // Switch to generator tab
        this.switchTab('generator');
    }

    showStatus(message, type = 'info') {
        const statusEl = document.getElementById('ai-generate-status');
        if (!statusEl) return;

        const colors = {
            info: '#a78bfa',
            error: '#fca5a5',
            success: '#86efac'
        };

        statusEl.textContent = message;
        statusEl.style.color = colors[type] || colors.info;

        if (type === 'success') {
            setTimeout(() => {
                statusEl.textContent = '';
            }, 3000);
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    getAuthToken() {
        const cookies = document.cookie.split(';');
        for (let cookie of cookies) {
            const [name, value] = cookie.trim().split('=');
            if (name === 'session_token') {
                return value;
            }
        }
        return null;
    }

    getCSRFToken() {
        // Get CSRF token from cookie
        const csrfCookie = document.cookie.split('; ').find(row => row.startsWith('csrf_token='));
        return csrfCookie ? csrfCookie.split('=')[1] : null;
    }
}

// Initialize AI Planner when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.aiPlanner = new AIPlanner();
});
