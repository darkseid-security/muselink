/**
 * AI Assistant - Gemini Pro 2.5 Integration
 * Handles chat interface, script analysis, and flowchart generation
 */

class AIAssistant {
    constructor() {
        this.modal = document.getElementById('ai-assistant-modal');
        this.chatMessages = document.getElementById('ai-chat-messages');
        this.chatInput = document.getElementById('ai-chat-input');
        this.sendBtn = document.getElementById('ai-send-btn');
        this.status = document.getElementById('ai-status');

        this.conversationHistory = [];
        this.isProcessing = false;

        this.init();
    }

    init() {
        // Open modal button
        document.getElementById('ai-assistant-btn').addEventListener('click', () => {
            this.openModal();
        });

        // Close modal button
        document.getElementById('close-ai-modal').addEventListener('click', () => {
            this.closeModal();
        });

        // Close on overlay click
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) {
                this.closeModal();
            }
        });

        // Send message
        this.sendBtn.addEventListener('click', () => {
            this.sendMessage();
        });

        // Enter to send (Shift+Enter for new line)
        this.chatInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });

        // Auto-resize textarea
        this.chatInput.addEventListener('input', () => {
            this.chatInput.style.height = 'auto';
            this.chatInput.style.height = this.chatInput.scrollHeight + 'px';

            // Enable/disable send button
            this.sendBtn.disabled = this.chatInput.value.trim().length === 0;
        });

        // Quick action buttons
        document.querySelectorAll('.ai-quick-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                this.handleQuickAction(btn.dataset.action);
            });
        });
    }

    openModal() {
        this.modal.classList.add('active');
        this.chatInput.focus();
    }

    closeModal() {
        this.modal.classList.remove('active');
    }

    async sendMessage() {
        const message = this.chatInput.value.trim();

        if (!message || this.isProcessing) return;

        // Add user message to chat
        this.addMessage(message, 'user');

        // Clear input
        this.chatInput.value = '';
        this.chatInput.style.height = 'auto';
        this.sendBtn.disabled = true;

        // Set processing state
        this.isProcessing = true;
        this.showTypingIndicator();

        try {
            // Call Gemini API
            const response = await this.callGeminiAPI(message);

            // Remove typing indicator
            this.hideTypingIndicator();

            if (response.success) {
                this.addMessage(response.response, 'assistant');
            } else {
                this.addMessage(
                    `I'm sorry, I encountered an error: ${response.error}. Please try again.`,
                    'assistant'
                );
            }
        } catch (error) {
            console.error('AI Assistant error:', error);
            this.hideTypingIndicator();
            this.addMessage(
                'I apologize, but I encountered an error. Please try again in a moment.',
                'assistant'
            );
        } finally {
            this.isProcessing = false;
        }
    }

    async callGeminiAPI(message, includeContext = true) {
        const token = this.getAuthToken();
        const csrfToken = this.getCSRFToken();

        const response = await fetch('/api/v1/gemini/chat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({
                message: message,
                include_context: includeContext
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'API request failed');
        }

        return await response.json();
    }

    async analyzeScript(ideaId) {
        this.showStatus('Analyzing script... This may take a moment.');

        const token = this.getAuthToken();
        const csrfToken = this.getCSRFToken();

        try {
            const response = await fetch('/api/v1/gemini/analyze-script', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`,
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({
                    idea_id: ideaId
                })
            });

            const data = await response.json();

            if (data.success) {
                this.displayAnalysisResults(data.analysis);
            } else {
                this.addMessage(
                    `Analysis failed: ${data.error}`,
                    'assistant'
                );
            }
        } catch (error) {
            console.error('Script analysis error:', error);
            this.addMessage(
                'Failed to analyze script. Please try again.',
                'assistant'
            );
        } finally {
            this.hideStatus();
        }
    }

    async generateFlowchart(description) {
        this.showStatus('Generating flowchart...');

        const token = this.getAuthToken();
        const csrfToken = this.getCSRFToken();

        try {
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
                this.addMessage(
                    `I've created a flowchart for you! Here's the Mermaid.js code:\n\n\`\`\`mermaid\n${data.mermaid}\n\`\`\`\n\nYou can use this in the Flowcharts tab.`,
                    'assistant'
                );
            } else {
                this.addMessage(
                    `Flowchart generation failed: ${data.error}`,
                    'assistant'
                );
            }
        } catch (error) {
            console.error('Flowchart generation error:', error);
            this.addMessage(
                'Failed to generate flowchart. Please try again.',
                'assistant'
            );
        } finally {
            this.hideStatus();
        }
    }

    displayAnalysisResults(analysis) {
        let message = '**Script Analysis Results**\n\n';

        if (analysis.overall_score) {
            message += `**Overall Score:** ${analysis.overall_score}/10\n`;
            message += `${analysis.overall_assessment}\n\n`;
        }

        if (analysis.pacing) {
            message += `**Pacing** (${analysis.pacing.score}/10)\n`;
            message += `${analysis.pacing.feedback}\n\n`;
        }

        if (analysis.character_development) {
            message += `**Character Development** (${analysis.character_development.score}/10)\n`;
            if (analysis.character_development.characters) {
                analysis.character_development.characters.forEach(char => {
                    message += `- **${char.name}**: ${char.feedback}\n`;
                });
            }
            message += '\n';
        }

        if (analysis.plot_structure) {
            message += `**Plot Structure** (${analysis.plot_structure.score}/10)\n`;
            if (analysis.plot_structure.strengths?.length) {
                message += '**Strengths:**\n';
                analysis.plot_structure.strengths.forEach(s => message += `- ${s}\n`);
            }
            if (analysis.plot_structure.weaknesses?.length) {
                message += '**Weaknesses:**\n';
                analysis.plot_structure.weaknesses.forEach(w => message += `- ${w}\n`);
            }
            message += '\n';
        }

        if (analysis.suggestions?.length) {
            message += '**Suggestions for Improvement:**\n';
            analysis.suggestions.forEach(sugg => {
                const priority = sugg.priority === 'high' ? '[HIGH]' :
                               sugg.priority === 'medium' ? '[MEDIUM]' : '[LOW]';
                message += `${priority} ${sugg.suggestion}\n`;
            });
        }

        this.addMessage(message, 'assistant');
    }

    async handleQuickAction(action) {
        switch (action) {
            case 'analyze':
                // Get user's latest script
                const latestIdea = await this.getLatestIdea();
                if (latestIdea) {
                    this.addMessage(`Analyzing "${latestIdea.title}"...`, 'user');
                    await this.analyzeScript(latestIdea.id);
                } else {
                    this.addMessage(
                        "You don't have any scripts to analyze yet. Create one in the Ideas tab!",
                        'assistant'
                    );
                }
                break;

            case 'brainstorm':
                this.chatInput.value = 'Help me brainstorm creative ideas for a screenplay';
                this.chatInput.focus();
                this.sendBtn.disabled = false;
                break;

            case 'flowchart':
                this.chatInput.value = 'Create a flowchart for ';
                this.chatInput.focus();
                this.sendBtn.disabled = false;
                break;
        }
    }

    async getLatestIdea() {
        const token = this.getAuthToken();

        try {
            const response = await fetch('/api/v1/ideas/my-ideas?limit=1', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            const data = await response.json();

            if (data.success && data.ideas && data.ideas.length > 0) {
                return data.ideas[0];
            }

            return null;
        } catch (error) {
            console.error('Error fetching latest idea:', error);
            return null;
        }
    }

    addMessage(content, role = 'user') {
        const messageDiv = document.createElement('div');
        messageDiv.className = `ai-message ai-message-${role}`;

        const avatar = document.createElement('div');
        avatar.className = 'ai-message-avatar';
        avatar.innerHTML = role === 'assistant'
            ? `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 2L2 7l10 5 10-5-10-5z"></path>
                <path d="M2 17l10 5 10-5M2 12l10 5 10-5"></path>
               </svg>`
            : `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                <circle cx="12" cy="7" r="4"></circle>
               </svg>`;

        const messageContent = document.createElement('div');
        messageContent.className = 'ai-message-content';
        messageContent.innerHTML = this.formatMessage(content);

        messageDiv.appendChild(avatar);
        messageDiv.appendChild(messageContent);

        this.chatMessages.appendChild(messageDiv);

        // Scroll to bottom
        this.chatMessages.scrollTop = this.chatMessages.scrollHeight;
    }

    formatMessage(content) {
        // Convert markdown-style formatting to HTML
        let formatted = content
            // Bold
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            // Priority badges
            .replace(/\[HIGH\]/g, '<span class="priority-badge priority-high">HIGH</span>')
            .replace(/\[MEDIUM\]/g, '<span class="priority-badge priority-medium">MEDIUM</span>')
            .replace(/\[LOW\]/g, '<span class="priority-badge priority-low">LOW</span>')
            // Code blocks
            .replace(/```(.*?)\n([\s\S]*?)```/g, '<pre><code class="language-$1">$2</code></pre>')
            // Inline code
            .replace(/`([^`]+)`/g, '<code>$1</code>')
            // Line breaks
            .replace(/\n/g, '<br>');

        return formatted;
    }

    showTypingIndicator() {
        const typingDiv = document.createElement('div');
        typingDiv.className = 'ai-message ai-message-assistant';
        typingDiv.id = 'typing-indicator';

        typingDiv.innerHTML = `
            <div class="ai-message-avatar">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 2L2 7l10 5 10-5-10-5z"></path>
                    <path d="M2 17l10 5 10-5M2 12l10 5 10-5"></path>
                </svg>
            </div>
            <div class="ai-message-content">
                <div class="ai-loading">
                    <span></span>
                    <span></span>
                    <span></span>
                </div>
            </div>
        `;

        this.chatMessages.appendChild(typingDiv);
        this.chatMessages.scrollTop = this.chatMessages.scrollHeight;
    }

    hideTypingIndicator() {
        const indicator = document.getElementById('typing-indicator');
        if (indicator) {
            indicator.remove();
        }
    }

    showStatus(message) {
        this.status.textContent = message;
        this.status.classList.add('typing');
    }

    hideStatus() {
        this.status.textContent = '';
        this.status.classList.remove('typing');
    }

    getAuthToken() {
        // Get session token from cookie
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

// Initialize AI Assistant when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.aiAssistant = new AIAssistant();
});
