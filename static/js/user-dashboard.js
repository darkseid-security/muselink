// Dashboard initialization
(() => {
    // Flask handles authentication server-side, no need for client-side session check
    // The welcome message is already personalized in the template via Jinja2

    // Logout button works via href="/logout" - no JavaScript needed
    // Flask handles session destruction
})();

// ===== UTILITY FUNCTIONS =====

/**
 * Escape HTML to prevent XSS attacks
 */
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Show image viewing modal
 */
async function showImageModal(imageId, imageData) {
    try {
        // Create image modal HTML
        const modalHTML = `
            <div class="modal-overlay" id="image-modal-overlay" style="
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.9);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 10000;
                backdrop-filter: blur(4px);
            ">
                <div class="modal-content" style="
                    background: #1a1a1a;
                    border-radius: 12px;
                    max-width: 90vw;
                    max-height: 90vh;
                    overflow: auto;
                    padding: 2rem;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.8);
                    position: relative;
                ">
                    <button class="modal-close-btn" onclick="document.getElementById('image-modal-overlay').remove()" style="
                        position: absolute;
                        top: 1rem;
                        right: 1rem;
                        background: rgba(255, 255, 255, 0.1);
                        border: 1px solid rgba(255, 255, 255, 0.2);
                        border-radius: 6px;
                        width: 36px;
                        height: 36px;
                        font-size: 1.5rem;
                        cursor: pointer;
                        color: #e2e8f0;
                        z-index: 10;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        transition: all 0.2s;
                    " onmouseover="this.style.background='rgba(255,255,255,0.2)'" onmouseout="this.style.background='rgba(255,255,255,0.1)'">&times;</button>

                    <div class="modal-header" style="margin-bottom: 1.5rem;">
                        <h2 style="margin: 0; color: #f1f5f9; display: flex; align-items: center; gap: 0.5rem;">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#60a5fa" stroke-width="2">
                                <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
                                <circle cx="8.5" cy="8.5" r="1.5"></circle>
                                <polyline points="21 15 16 10 5 21"></polyline>
                            </svg>
                            ${escapeHtml(imageData.title || 'Generated Image')}
                        </h2>
                        <p style="color: #94a3b8; margin: 0.5rem 0 0 0; font-size: 0.95rem;">
                            Created: ${new Date(imageData.created_at).toLocaleString()}
                        </p>
                    </div>

                    <div class="modal-body" style="text-align: center;">
                        <img src="${imageData.image_url}" alt="Generated Image" style="
                            max-width: 100%;
                            max-height: 70vh;
                            border-radius: 8px;
                            box-shadow: 0 8px 24px rgba(0,0,0,0.5);
                            margin-bottom: 1.5rem;
                        ">

                        <div style="text-align: left; background: rgba(255, 255, 255, 0.05); padding: 1.5rem; border-radius: 8px; margin-top: 1rem; border: 1px solid rgba(255, 255, 255, 0.1);">
                            <h3 style="color: #cbd5e1; font-size: 1rem; margin-bottom: 0.75rem;">Image Details</h3>
                            <p style="margin: 0.5rem 0; color: #94a3b8;"><strong style="color: #e2e8f0;">Prompt:</strong> ${escapeHtml(imageData.prompt || 'N/A')}</p>
                            ${imageData.style ? `<p style="margin: 0.5rem 0; color: #94a3b8;"><strong style="color: #e2e8f0;">Style:</strong> ${escapeHtml(imageData.style)}</p>` : ''}
                            ${imageData.aspect_ratio ? `<p style="margin: 0.5rem 0; color: #94a3b8;"><strong style="color: #e2e8f0;">Aspect Ratio:</strong> ${escapeHtml(imageData.aspect_ratio)}</p>` : ''}
                        </div>
                    </div>

                    <div class="modal-footer" style="margin-top: 1.5rem; display: flex; gap: 0.75rem; justify-content: flex-end;">
                        <button class="btn" onclick="document.getElementById('image-modal-overlay').remove()" style="background: rgba(255, 255, 255, 0.1); color: #e2e8f0; border: 1px solid rgba(255, 255, 255, 0.2);">Close</button>
                        <button class="btn btn-primary" onclick="downloadImage('${imageData.image_url}', 'image-${imageId}.jpg')" style="background: linear-gradient(90deg, #F17A4D, #F7A382); color: white; border: none; box-shadow: 0 4px 15px -5px #F17A4D; transition: all 0.2s; padding: 0.75rem 1.5rem; border-radius: 8px; font-weight: 500; cursor: pointer;" onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 6px 20px -5px #F17A4D'; this.style.filter='brightness(1.1)';" onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 4px 15px -5px #F17A4D'; this.style.filter='brightness(1)';">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 0.5rem;">
                                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                                <polyline points="7 10 12 15 17 10"></polyline>
                                <line x1="12" y1="15" x2="12" y2="3"></line>
                            </svg>
                            Download
                        </button>
                    </div>
                </div>
            </div>
        `;

        // Add modal to body
        document.body.insertAdjacentHTML('beforeend', modalHTML);

        // Close on overlay click
        document.getElementById('image-modal-overlay').addEventListener('click', (e) => {
            if (e.target.id === 'image-modal-overlay') {
                e.target.remove();
            }
        });
    } catch (error) {
        console.error('Failed to show image modal:', error);
        showFlash('Failed to display image: ' + error.message, 'error');
    }
}

/**
 * Download image with proper filename
 */
function downloadImage(imageUrl, filename) {
    fetch(imageUrl)
        .then(response => response.blob())
        .then(blob => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            showFlash('Image download started', 'success');
        })
        .catch(error => {
            console.error('Download failed:', error);
            showFlash('Failed to download image', 'error');
        });
}

/**
 * Navigate to My Ideas page
 */
function loadMyIdeas() {
    console.log('📢 loadMyIdeas called - navigating to My Ideas tab');

    // Find the My Ideas nav item and simulate a click
    const myIdeasNavItem = document.querySelector('[data-page="my-ideas-page"]');
    if (myIdeasNavItem) {
        console.log('📢 Found My Ideas nav item, clicking it');
        myIdeasNavItem.click();
    } else {
        console.log('📢 Nav item not found, using fallback method');
        // Fallback: manually show the page
        // Hide all pages
        document.querySelectorAll('.page').forEach(page => {
            page.classList.remove('active');
            page.style.display = 'none';
        });

        // Show My Ideas page
        const myIdeasPage = document.getElementById('my-ideas-page');
        if (myIdeasPage) {
            myIdeasPage.classList.add('active');
            myIdeasPage.style.display = 'block';
            console.log('📢 My Ideas page displayed');
        }

        // Update nav items
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });
        if (myIdeasNavItem) {
            myIdeasNavItem.classList.add('active');
        }
    }
}

// Make it globally available
window.loadMyIdeas = loadMyIdeas;

/**
 * Show video viewing modal
 */
async function showVideoModal(ideaId, ideaData, videoUrl) {
    try {
        // Create video modal HTML
        const modalHTML = `
            <div class="modal-overlay" id="video-modal-overlay" style="
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.95);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 10000;
                backdrop-filter: blur(4px);
            ">
                <div class="modal-content" style="
                    background: #1a1a1a;
                    border-radius: 12px;
                    max-width: 90vw;
                    max-height: 90vh;
                    overflow: auto;
                    padding: 2rem;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.8);
                    position: relative;
                ">
                    <button class="modal-close-btn" onclick="document.getElementById('video-modal-overlay').remove()" style="
                        position: absolute;
                        top: 1rem;
                        right: 1rem;
                        background: rgba(255, 255, 255, 0.1);
                        border: 1px solid rgba(255, 255, 255, 0.2);
                        border-radius: 6px;
                        width: 36px;
                        height: 36px;
                        font-size: 1.5rem;
                        cursor: pointer;
                        color: #e2e8f0;
                        z-index: 10;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        transition: all 0.2s;
                    " onmouseover="this.style.background='rgba(255,255,255,0.2)'" onmouseout="this.style.background='rgba(255,255,255,0.1)'">&times;</button>

                    <div class="modal-header" style="margin-bottom: 1.5rem;">
                        <h2 style="margin: 0; color: #f1f5f9; display: flex; align-items: center; gap: 0.5rem;">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#60a5fa" stroke-width="2">
                                <polygon points="23 7 16 12 23 17 23 7"></polygon>
                                <rect x="1" y="5" width="15" height="14" rx="2" ry="2"></rect>
                            </svg>
                            ${escapeHtml(ideaData.title || 'Generated Video')}
                        </h2>
                        <p style="color: #94a3b8; margin: 0.5rem 0 0 0; font-size: 0.95rem;">
                            Duration: ${ideaData.video_duration || 'N/A'}s | Aspect Ratio: ${ideaData.video_aspect_ratio || 'N/A'}
                        </p>
                        <p style="color: #94a3b8; margin: 0.25rem 0 0 0; font-size: 0.85rem;">
                            Created: ${new Date(ideaData.created_at).toLocaleString()}
                        </p>
                    </div>

                    <div class="modal-body" style="text-align: center;">
                        <video controls autoplay style="
                            max-width: 100%;
                            max-height: 65vh;
                            border-radius: 8px;
                            box-shadow: 0 8px 24px rgba(0,0,0,0.5);
                            margin-bottom: 1.5rem;
                            background: #000;
                        ">
                            <source src="${videoUrl}" type="video/mp4">
                            Your browser does not support the video tag.
                        </video>

                        ${ideaData.video_prompt ? `
                        <div style="text-align: left; background: rgba(255, 255, 255, 0.05); padding: 1.5rem; border-radius: 8px; margin-top: 1rem; border: 1px solid rgba(255, 255, 255, 0.1);">
                            <h3 style="color: #cbd5e1; font-size: 1rem; margin-bottom: 0.75rem;">Video Details</h3>
                            <p style="margin: 0.5rem 0; color: #94a3b8;"><strong style="color: #e2e8f0;">Prompt:</strong> ${escapeHtml(ideaData.video_prompt)}</p>
                        </div>
                        ` : ''}
                    </div>

                    <div class="modal-footer" style="margin-top: 1.5rem; display: flex; gap: 0.75rem; justify-content: flex-end;">
                        <button class="btn" onclick="document.getElementById('video-modal-overlay').remove()" style="background: rgba(255, 255, 255, 0.1); color: #e2e8f0; border: 1px solid rgba(255, 255, 255, 0.2);">Close</button>
                        <button class="btn btn-primary" onclick="downloadVideo('${videoUrl}', 'video-${ideaId}.mp4')" style="background: linear-gradient(90deg, #F17A4D, #F7A382); color: white; border: none; box-shadow: 0 4px 15px -5px #F17A4D; transition: all 0.2s; padding: 0.75rem 1.5rem; border-radius: 8px; font-weight: 500; cursor: pointer;" onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 6px 20px -5px #F17A4D'; this.style.filter='brightness(1.1)';" onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 4px 15px -5px #F17A4D'; this.style.filter='brightness(1)';">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 0.5rem;">
                                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                                <polyline points="7 10 12 15 17 10"></polyline>
                                <line x1="12" y1="15" x2="12" y2="3"></line>
                            </svg>
                            Download
                        </button>
                    </div>
                </div>
            </div>
        `;

        // Add modal to body
        document.body.insertAdjacentHTML('beforeend', modalHTML);

        // Close on overlay click
        document.getElementById('video-modal-overlay').addEventListener('click', (e) => {
            if (e.target.id === 'video-modal-overlay') {
                e.target.remove();
            }
        });
    } catch (error) {
        console.error('Failed to show video modal:', error);
        showFlash('Failed to display video: ' + error.message, 'error');
    }
}

/**
 * Download video with proper filename
 */
function downloadVideo(videoUrl, filename) {
    fetch(videoUrl)
        .then(response => response.blob())
        .then(blob => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            showFlash('Video download started', 'success');
        })
        .catch(error => {
            console.error('Download failed:', error);
            showFlash('Failed to download video', 'error');
        });
}

/**
 * Show idea detail modal with full script content
 */
async function showIdeaModal(ideaId) {
    try {
        // Fetch full idea details
        const response = await API.getIdeaDetail(ideaId);

        if (!response.success) {
            showFlash('Failed to load idea details', 'error');
            return;
        }

        const idea = response.idea;

        // Create modal HTML with dark theme
        const modalHTML = `
            <div class="modal-overlay" id="idea-modal-overlay" style="
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.85);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 10000;
                backdrop-filter: blur(8px);
            ">
                <div class="modal-content" style="
                    background: #1a1a1a;
                    border-radius: 16px;
                    max-width: 900px;
                    max-height: 90vh;
                    overflow-y: auto;
                    padding: 2rem;
                    box-shadow: 0 25px 80px rgba(0, 0, 0, 0.6);
                    border: 1px solid rgba(100, 116, 139, 0.2);
                    position: relative;
                ">
                    <button class="modal-close-btn" onclick="document.getElementById('idea-modal-overlay').remove()" style="
                        position: absolute;
                        top: 1rem;
                        right: 1rem;
                        background: rgba(100, 116, 139, 0.1);
                        border: 1px solid rgba(100, 116, 139, 0.2);
                        border-radius: 8px;
                        width: 36px;
                        height: 36px;
                        font-size: 1.5rem;
                        cursor: pointer;
                        color: #94a3b8;
                        transition: all 0.2s;
                    " onmouseover="this.style.background='rgba(248, 113, 113, 0.2)'; this.style.color='#f87171';"
                       onmouseout="this.style.background='rgba(100, 116, 139, 0.1)'; this.style.color='#94a3b8';">&times;</button>

                    <div class="modal-header" style="margin-bottom: 1.5rem;">
                        <h2 style="margin: 0; color: #f1f5f9; display: flex; align-items: center; gap: 0.5rem;">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2z"></path>
                                <path d="M12 6v6l4 2"></path>
                            </svg>
                            ${escapeHtml(idea.title)}
                        </h2>
                        <p style="color: #94a3b8; margin: 0.5rem 0 0 0; font-size: 0.95rem;">
                            Created: ${new Date(idea.created_at).toLocaleString()}
                            ${idea.is_pinned ? ' <span style="color: #f59e0b;">📌 Pinned</span>' : ''}
                        </p>
                    </div>

                    ${idea.description ? `
                        <div class="modal-section" style="margin-bottom: 1.5rem;">
                            <h3 style="color: #94a3b8; font-size: 1rem; margin-bottom: 0.5rem;">Description</h3>
                            <p style="color: #cbd5e1; line-height: 1.6;">${escapeHtml(idea.description)}</p>
                        </div>
                    ` : ''}

                    <div class="modal-section">
                        <h3 style="color: #94a3b8; font-size: 1rem; margin-bottom: 0.75rem;">Generated Script</h3>
                        <div style="
                            background: rgba(30, 41, 59, 0.4);
                            border: 1px solid rgba(100, 116, 139, 0.2);
                            border-radius: 8px;
                            padding: 1.5rem;
                            white-space: pre-wrap;
                            font-family: 'Courier New', monospace;
                            font-size: 0.9rem;
                            line-height: 1.8;
                            color: #e2e8f0;
                            max-height: 500px;
                            overflow-y: auto;
                        ">${escapeHtml(idea.content)}</div>
                    </div>

                    <div class="modal-footer" style="margin-top: 2rem; display: flex; gap: 1rem; justify-content: flex-end;">
                        <button onclick="document.getElementById('idea-modal-overlay').remove()" style="
                            padding: 0.75rem 1.5rem;
                            border-radius: 8px;
                            font-weight: 500;
                            cursor: pointer;
                            transition: all 0.2s;
                            background: rgba(100, 116, 139, 0.1);
                            border: 1px solid rgba(100, 116, 139, 0.2);
                            color: #cbd5e1;
                        " onmouseover="this.style.background='rgba(100, 116, 139, 0.2)';"
                           onmouseout="this.style.background='rgba(100, 116, 139, 0.1)';">Close</button>
                        ${idea.content_type === 'voice' ? `
                        <button id="play-audio-btn" data-idea-id="${idea.id}" style="
                            padding: 0.75rem 1.5rem;
                            border-radius: 8px;
                            font-weight: 500;
                            cursor: pointer;
                            transition: all 0.2s;
                            background: linear-gradient(90deg, #ff7f50, #ff6347);
                            border: none;
                            color: white;
                            box-shadow: 0 4px 15px -5px #ff7f50;
                            display: flex;
                            align-items: center;
                            gap: 0.5rem;
                        " onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 6px 20px -5px #ff7f50'; this.style.filter='brightness(1.1)';"
                           onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 4px 15px -5px #ff7f50'; this.style.filter='brightness(1)';">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                            Play Audio
                        </button>
                        ` : `
                        <button onclick="navigator.clipboard.writeText(${JSON.stringify(idea.content).replace(/"/g, '&quot;')}); showFlash('Script copied to clipboard!', 'success')" style="
                            padding: 0.75rem 1.5rem;
                            border-radius: 8px;
                            font-weight: 500;
                            cursor: pointer;
                            transition: all 0.2s;
                            background: linear-gradient(90deg, #F17A4D, #F7A382);
                            border: none;
                            color: white;
                            box-shadow: 0 4px 15px -5px #F17A4D;
                        " onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 6px 20px -5px #F17A4D'; this.style.filter='brightness(1.1)';"
                           onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 4px 15px -5px #F17A4D'; this.style.filter='brightness(1)';">
                            Copy Script
                        </button>
                        `}
                    </div>
                </div>
            </div>
        `;

        // Append modal to body
        document.body.insertAdjacentHTML('beforeend', modalHTML);

        // Close on overlay click
        document.getElementById('idea-modal-overlay').addEventListener('click', (e) => {
            if (e.target.id === 'idea-modal-overlay') {
                e.target.remove();
            }
        });

        // Add play audio button handler for voice content
        const playAudioBtn = document.getElementById('play-audio-btn');
        if (playAudioBtn) {
            playAudioBtn.addEventListener('click', () => {
                const ideaId = playAudioBtn.dataset.ideaId;
                const voicePath = `/api/v1/ideas/voice/${ideaId}/download`;

                // Update button to show playing state
                const originalHTML = playAudioBtn.innerHTML;
                playAudioBtn.innerHTML = `
                    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <rect x="6" y="4" width="4" height="16"></rect>
                        <rect x="14" y="4" width="4" height="16"></rect>
                    </svg>
                    Playing...
                `;
                playAudioBtn.disabled = true;
                playAudioBtn.style.opacity = '0.7';

                const audio = new Audio(voicePath);

                audio.play().then(() => {
                    showFlash('Playing audio...', 'info');
                }).catch(err => {
                    console.error('Audio playback failed:', err);
                    showFlash('Failed to play audio', 'error');
                    playAudioBtn.innerHTML = originalHTML;
                    playAudioBtn.disabled = false;
                    playAudioBtn.style.opacity = '1';
                });

                // Reset button when audio ends
                audio.addEventListener('ended', () => {
                    playAudioBtn.innerHTML = originalHTML;
                    playAudioBtn.disabled = false;
                    playAudioBtn.style.opacity = '1';
                });
            });
        }
    } catch (error) {
        console.error('Failed to show idea modal:', error);
        showFlash('Failed to load idea: ' + error.message, 'error');
    }
}

/**
 * Handle idea/image deletion with modern confirmation modal
 */
async function handleDeleteIdea(ideaId, contentType = 'text') {
    // Get the item details to show the title
    let itemTitle = '';
    let itemType = 'idea';

    try {
        if (contentType === 'image') {
            // For images, we already have the title in the row
            const row = document.querySelector(`[data-id="${ideaId}"][data-content-type="image"]`);
            if (row) {
                itemTitle = row.querySelector('.idea-title-cell strong')?.textContent || 'this image';
            } else {
                itemTitle = 'this image';
            }
            itemType = 'image';
        } else {
            // For ideas, fetch details from API
            const ideaResponse = await API.getIdeaDetail(ideaId);
            itemTitle = ideaResponse.idea?.title || 'Untitled Idea';
            itemType = 'idea';
        }

        // Update modal with item title
        document.getElementById('delete-idea-title').textContent = itemTitle;
    } catch (error) {
        document.getElementById('delete-idea-title').textContent = contentType === 'image' ? 'this image' : 'this idea';
    }

    // Store idea ID and content type in confirm button's dataset
    const confirmBtn = document.getElementById('confirm-delete-idea-btn');
    confirmBtn.dataset.ideaId = ideaId;
    confirmBtn.dataset.contentType = contentType;

    // Reset checkbox and disable button
    const checkbox = document.getElementById('confirm-delete-checkbox');
    if (checkbox) {
        checkbox.checked = false;
    }
    confirmBtn.disabled = true;

    // Hide error message
    document.getElementById('delete-idea-error').style.display = 'none';

    // Show modal using active classes
    const overlay = document.getElementById('delete-idea-modal-overlay');
    const modal = document.getElementById('delete-idea-modal');
    overlay.classList.add('active');
    modal.classList.add('active');
}

/**
 * Handle team assignment button click
 */
async function handleAssignToTeam(ideaId) {
    // Store idea ID in confirm button's dataset
    const confirmBtn = document.getElementById('confirm-assign-team-btn');
    confirmBtn.dataset.ideaId = ideaId;

    // Show loading state
    document.getElementById('assign-team-loading').style.display = 'block';
    document.getElementById('assign-team-content').style.display = 'none';
    document.getElementById('assign-team-error').style.display = 'none';
    document.getElementById('assign-team-success').style.display = 'none';

    // Show modal using active classes
    const overlay = document.getElementById('assign-team-modal-overlay');
    const modal = document.getElementById('assign-team-modal');
    overlay.classList.add('active');
    modal.classList.add('active');

    try {
        // Fetch user's teams
        const teamsResponse = await API.getTeams();
        const teams = teamsResponse.teams || [];

        // Populate team select
        const selectElement = document.getElementById('assign-team-select');
        selectElement.innerHTML = '<option value="">-- Select a Team --</option>';

        if (teams.length === 0) {
            document.getElementById('assign-team-loading').style.display = 'none';
            document.getElementById('assign-team-error').textContent = 'You are not a member of any teams yet. Create or join a team first.';
            document.getElementById('assign-team-error').style.display = 'block';
            return;
        }

        teams.forEach(team => {
            const option = document.createElement('option');
            option.value = team.id;
            option.textContent = `${team.name} (${team.role})`;
            selectElement.appendChild(option);
        });

        // Show content
        document.getElementById('assign-team-loading').style.display = 'none';
        document.getElementById('assign-team-content').style.display = 'block';
        document.getElementById('assign-team-info').style.display = 'block';

    } catch (error) {
        console.error('Failed to load teams:', error);
        document.getElementById('assign-team-loading').style.display = 'none';
        document.getElementById('assign-team-error').textContent = 'Failed to load teams: ' + error.message;
        document.getElementById('assign-team-error').style.display = 'block';
    }
}

/**
 * Handle idea status change
 */
async function handleStatusChange(ideaId, newStatus) {
    try {
        const response = await API.updateIdeaStatus(ideaId, newStatus);

        if (response.success) {
            showFlash('Status updated successfully', 'success');

            // Update cache with new status
            const idea = cache.ideas.find(i => i.id === ideaId);
            if (idea) {
                idea.status = newStatus;
            }

            // Update the status badge in the UI without full refresh
            const row = document.querySelector(`tr[data-id="${ideaId}"]`);
            if (row) {
                const statusBadgeCell = row.querySelector('td:nth-child(2)');
                if (statusBadgeCell) {
                    const statusColors = {
                        'draft': '#94a3b8',
                        'in_progress': '#3b82f6',
                        'review': '#f59e0b',
                        'completed': '#10b981'
                    };
                    const statusLabels = {
                        'draft': 'Draft',
                        'in_progress': 'In Progress',
                        'review': 'Review',
                        'completed': 'Completed'
                    };
                    const color = statusColors[newStatus] || '#94a3b8';
                    const label = statusLabels[newStatus] || newStatus;
                    statusBadgeCell.innerHTML = `<span style="
                        display: inline-block;
                        padding: 0.25rem 0.75rem;
                        border-radius: 12px;
                        background-color: ${color}15;
                        color: ${color};
                        font-size: 0.85rem;
                        font-weight: 500;
                    ">${label}</span>`;
                }
            }
        } else {
            throw new Error(response.message || 'Status update failed');
        }
    } catch (error) {
        console.error('Failed to update status:', error);
        showFlash('Failed to update status: ' + error.message, 'error');

        // Refresh to restore original status on error
        cache.lastFetch.ideas = 0;
        await renderAllIdeas();
    }
}

// ===== API HELPER FUNCTIONS =====
const API = {
    // Helper to get CSRF token from cookie
    getCSRFToken() {
        const csrfCookie = document.cookie.split('; ').find(row => row.startsWith('csrf_token='));
        return csrfCookie ? csrfCookie.split('=')[1] : null;
    },

    // Generic fetch wrapper with CSRF protection
    // Note: session_token is httpOnly and sent automatically by browser in cookies
    async request(endpoint, options = {}) {
        const csrfToken = this.getCSRFToken();

        // Debug logging
        console.log('🔐 CSRF Token:', csrfToken ? 'PRESENT' : 'MISSING');
        if (!csrfToken) {
            console.error('❌ CSRF token missing! Cookies:', document.cookie);
        }

        const headers = {
            'Content-Type': 'application/json',
            ...(csrfToken && { 'X-CSRF-Token': csrfToken }),
            ...options.headers
        };

        console.log('📤 Request Headers:', headers);

        try {
            const response = await fetch(endpoint, {
                ...options,
                headers
            });

            if (!response.ok) {
                if (response.status === 401) {
                    // Unauthorized - redirect to login
                    window.location.href = '/auth?redirect=' + encodeURIComponent(window.location.pathname);
                    return null;
                }
                // Try to get detailed error message from server
                const errorData = await response.json().catch(() => ({}));
                if (response.status === 403 && errorData.detail && errorData.detail.includes('CSRF')) {
                    throw new Error('Security validation failed. Please refresh the page.');
                }

                // Handle validation errors (422) with field-specific messages
                if (response.status === 422 && errorData.details && Array.isArray(errorData.details)) {
                    const fieldErrors = errorData.details.map(e => `${e.field}: ${e.message}`).join('; ');
                    const errorMessage = `Validation Error - ${fieldErrors}`;
                    throw new Error(errorMessage);
                }

                // Throw with server's error detail if available
                const errorMessage = errorData.detail || errorData.error || `HTTP ${response.status}: ${response.statusText}`;
                throw new Error(errorMessage);
            }

            return await response.json();
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    },

    // User API
    async getUserProfile() {
        return await this.request('/api/v1/user/profile');
    },

    // Ideas API
    async getIdeas() {
        return await this.request('/api/v1/drive/ideas');
    },

    async createIdea(ideaData) {
        return await this.request('/api/v1/drive/ideas', {
            method: 'POST',
            body: JSON.stringify(ideaData)
        });
    },

    async addContributor(ideaId, contributorData) {
        return await this.request(`/api/v1/drive/ideas/${ideaId}/contributors`, {
            method: 'POST',
            body: JSON.stringify(contributorData)
        });
    },

    // AI Script Generation API
    async generateScript(scriptData) {
        return await this.request('/api/v1/ideas/generate-script', {
            method: 'POST',
            body: JSON.stringify(scriptData)
        });
    },

    // AI Image Generation API
    async generateImage(imageData) {
        return await this.request('/api/v1/ideas/generate-image', {
            method: 'POST',
            body: JSON.stringify(imageData)
        });
    },

    async getMyImages(limit = 50, offset = 0) {
        const cacheBuster = Date.now();
        const url = `/api/v1/ideas/my-images?limit=${limit}&offset=${offset}&_=${cacheBuster}`;
        return await this.request(url);
    },

    async getMyIdeas(limit = 50, offset = 0) {
        // Add cache buster to force fresh data
        const cacheBuster = Date.now();
        const url = `/api/v1/ideas/my-ideas?limit=${limit}&offset=${offset}&_=${cacheBuster}`;
        console.log('🔍 Calling endpoint:', url);
        return await this.request(url);
    },

    async getTeamIdeas(limit = 50, offset = 0) {
        // Get ideas assigned to user's teams
        const cacheBuster = Date.now();
        return await this.request(`/api/v1/ideas/team-ideas?limit=${limit}&offset=${offset}&_=${cacheBuster}`);
    },

    async getIdeaDetail(ideaId) {
        return await this.request(`/api/v1/ideas/idea/${ideaId}`);
    },

    async deleteIdea(ideaId) {
        return await this.request(`/api/v1/ideas/idea/${ideaId}`, {
            method: 'DELETE'
        });
    },

    async updateIdeaStatus(ideaId, status) {
        return await this.request(`/api/v1/ideas/idea/${ideaId}/status`, {
            method: 'PUT',
            body: JSON.stringify({ status })
        });
    },

    async assignIdeaToTeam(ideaId, teamId) {
        return await this.request(`/api/v1/ideas/idea/${ideaId}/assign-team`, {
            method: 'POST',
            body: JSON.stringify({ team_id: teamId })
        });
    },

    async getIdeaTeams(ideaId) {
        return await this.request(`/api/v1/ideas/idea/${ideaId}/teams`);
    },

    // Teams API
    async getTeams() {
        return await this.request('/api/v1/drive/teams');
    },

    async createTeam(teamData) {
        return await this.request('/api/v1/drive/teams', {
            method: 'POST',
            body: JSON.stringify(teamData)
        });
    },

    async addTeamMember(teamId, memberData) {
        return await this.request(`/api/v1/drive/teams/${teamId}/members`, {
            method: 'POST',
            body: JSON.stringify(memberData)
        });
    },

    // Messages API
    async getInboxMessages() {
        return await this.request('/api/v1/messages/inbox');
    },

    async getSentMessages() {
        return await this.request('/api/v1/messages/sent');
    },

    async getMessage(messageId) {
        return await this.request(`/api/v1/messages/${messageId}`);
    },

    async sendMessage(messageData) {
        return await this.request('/api/v1/messages/send', {
            method: 'POST',
            body: JSON.stringify(messageData)
        });
    },

    async getUnreadCount() {
        return await this.request('/api/v1/messages/unread/count');
    },

    // Drive/Notes API
    async getNotes() {
        return await this.request('/api/v1/drive/notes');
    },

    async getNote(noteId) {
        return await this.request(`/api/v1/drive/notes/${noteId}`);
    },

    async getFiles(teamId = null) {
        const params = teamId ? `?team_id=${teamId}` : '';
        return await this.request(`/api/v1/drive/files${params}`);
    },

    async createNote(noteData) {
        return await this.request('/api/v1/drive/notes', {
            method: 'POST',
            body: JSON.stringify(noteData)
        });
    },

    async updateNote(noteId, noteData) {
        return await this.request(`/api/v1/drive/notes/${noteId}`, {
            method: 'PUT',
            body: JSON.stringify(noteData)
        });
    },

    async deleteNote(noteId) {
        return await this.request(`/api/v1/drive/notes/${noteId}`, {
            method: 'DELETE'
        });
    },

    // Files API
    async uploadFile(formData) {
        // Get CSRF token for security
        const csrfToken = this.getCSRFToken();

        // Debug logging
        console.log('🔐 uploadFile - CSRF Token:', csrfToken ? 'PRESENT' : 'MISSING');
        console.log('📤 uploadFile - CSRF Token Value:', csrfToken);

        // Prepare headers (don't set Content-Type for FormData - browser will set it with boundary)
        const headers = {};
        if (csrfToken) {
            headers['X-CSRF-Token'] = csrfToken;
        }

        console.log('📤 uploadFile - Headers Object:', headers);

        // Session token is sent automatically by browser in httpOnly cookie
        const response = await fetch('/api/v1/drive/files/upload', {
            method: 'POST',
            credentials: 'same-origin',  // Include cookies
            headers: headers,
            body: formData
        });

        if (!response.ok) {
            // Try to get detailed error message from server
            try {
                const errorData = await response.json();
                throw new Error(errorData.detail || `Upload failed: ${response.statusText}`);
            } catch (e) {
                throw new Error(`Upload failed: ${response.statusText}`);
            }
        }

        return await response.json();
    },

    async downloadFile(fileId) {
        // Session token is sent automatically by browser in httpOnly cookie
        return await fetch(`/api/v1/drive/files/${fileId}/download`, {
            credentials: 'same-origin'  // Include cookies
        });
    },

    // Settings API
    async changeEmail(emailData) {
        return await this.request('/api/v1/user/settings/change-email', {
            method: 'POST',
            body: JSON.stringify(emailData)
        });
    },

    // MFA Methods (using auth.py endpoints with cookie authentication)
    async setupMFA() {
        // GET /api/v1/auth/mfa/setup - generates QR code and secret
        // Session token cookie is sent automatically by browser (httpOnly)
        const response = await fetch('/api/v1/auth/mfa/setup', {
            method: 'GET',
            credentials: 'same-origin'  // Include cookies
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.detail || `HTTP ${response.status}: ${response.statusText}`);
        }

        return await response.json();
    },

    async enableMFA(mfaCode) {
        // POST /api/v1/auth/mfa/enable - verifies code and enables MFA
        // Session token cookie is sent automatically by browser (httpOnly)
        // Use API.request() wrapper to include CSRF token
        return await this.request('/api/v1/auth/mfa/enable', {
            method: 'POST',
            credentials: 'same-origin',  // Include cookies
            body: JSON.stringify({ mfa_code: mfaCode })
        });
    },

    async getMFAStatus() {
        // GET /api/v1/user/settings/mfa/status - get MFA status
        return await this.request('/api/v1/user/settings/mfa/status', {
            method: 'GET',
            credentials: 'same-origin'  // Include cookies
        });
    }
};

// ===== CACHE FOR FREQUENTLY ACCESSED DATA =====
const cache = {
    currentUser: null,
    ideas: [],
    teams: [],
    messages: [],
    notes: [],
    lastFetch: {}
};

// Track current folder ID and team ID for uploads
let currentFolderId = null;
let currentTeamId = null;

// Cache helper - refresh data if older than 5 minutes
function shouldRefreshCache(key) {
    const lastFetch = cache.lastFetch[key];
    if (!lastFetch) return true;
    return (Date.now() - lastFetch) > 300000; // 5 minutes
}

function updateCache(key, data) {
    cache[key] = data;
    cache.lastFetch[key] = Date.now();
}

// ===== FLASH MESSAGE SYSTEM =====
function showFlash(message, type = 'info', duration = 5000) {
    const container = document.getElementById('flash-messages');
    if (!container) return;

    const icons = {
        success: '✓',
        error: '✕',
        warning: '⚠',
        info: 'ℹ'
    };

    const flashDiv = document.createElement('div');
    flashDiv.className = `flash-message ${type}`;
    flashDiv.innerHTML = `
        <span class="flash-message-icon">${icons[type] || icons.info}</span>
        <span class="flash-message-content">${message}</span>
        <button class="flash-message-close" onclick="this.parentElement.remove()">&times;</button>
    `;

    container.appendChild(flashDiv);

    // Auto-remove after duration
    setTimeout(() => {
        flashDiv.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => flashDiv.remove(), 300);
    }, duration);
}

// Delete File Modal Functions
let pendingFileDelete = null;
let currentViewTeamId = null; // Track current team view to prevent redirect

function openDeleteFileModal(itemId, itemType, fileName) {
    const modal = document.getElementById('delete-file-modal-overlay');
    const title = document.getElementById('delete-file-title');
    const message = document.getElementById('delete-file-message');
    const confirmBtn = document.getElementById('confirm-delete-file-btn');

    // Store pending delete info
    pendingFileDelete = { itemId, itemType, fileName };

    // Update modal content
    const typeLabel = itemType === 'folder' ? 'Folder' : itemType === 'note' ? 'Note' : 'File';
    title.textContent = `Delete ${typeLabel}`;
    message.textContent = `Are you sure you want to delete "${fileName}"? This action cannot be undone.`;

    // Show modal
    modal.classList.add('active');
    modal.style.display = 'grid';

    // Note: Button handler is set up once in DOMContentLoaded, not here
}

function closeDeleteFileModal() {
    const modal = document.getElementById('delete-file-modal-overlay');
    modal.classList.remove('active');
    setTimeout(() => {
        modal.style.display = 'none';
    }, 300);
    pendingFileDelete = null;
}

async function confirmDeleteFile() {
    if (!pendingFileDelete) return;

    const { itemId, itemType, fileName } = pendingFileDelete;
    const confirmBtn = document.getElementById('confirm-delete-file-btn');

    // Clear pending delete immediately to prevent double-deletion
    pendingFileDelete = null;

    // Disable button during deletion
    confirmBtn.disabled = true;
    confirmBtn.textContent = 'Deleting...';

    try {
        if (itemType === 'note') {
            await API.deleteNote(itemId);
            showFlash('Note deleted successfully', 'success');
        } else if (itemType === 'file') {
            await API.request(`/api/v1/drive/files/${itemId}`, { method: 'DELETE' });
            showFlash('File deleted successfully', 'success');
        } else if (itemType === 'folder') {
            await API.request(`/api/v1/drive/folders/${itemId}`, { method: 'DELETE' });
            showFlash('Folder deleted successfully', 'success');
        }

        closeDeleteFileModal();

        // Refresh the current view (personal or team drive) without redirecting
        await renderDrive();
    } catch (error) {
        showFlash('Failed to delete item: ' + error.message, 'error');
        closeDeleteFileModal();
    } finally {
        // Re-enable button
        confirmBtn.disabled = false;
        confirmBtn.textContent = 'Delete';
    }
}

// Export for global access
window.openDeleteFileModal = openDeleteFileModal;
window.closeDeleteFileModal = closeDeleteFileModal;
window.confirmDeleteFile = confirmDeleteFile;

// Close modal on click outside
document.addEventListener('click', (e) => {
    const modal = document.getElementById('delete-file-modal-overlay');
    if (e.target === modal) {
        closeDeleteFileModal();
    }
});

// Close modal on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeDeleteFileModal();
    }
});

document.addEventListener('DOMContentLoaded', async () => {
    console.log('Dashboard JavaScript loaded');

    // ===== MODAL HELPER FUNCTION =====
    const closeModal = (overlayId) => {
        const overlay = document.getElementById(overlayId);
        if (!overlay) return;

        const modal = overlay.querySelector('.modal');

        // Remove classes
        overlay.classList.remove('active');
        if (modal) modal.classList.remove('active');

        // Clear inline styles
        overlay.style.display = '';
        overlay.style.opacity = '';
        overlay.style.zIndex = '';
        if (modal) {
            modal.style.display = '';
            modal.style.opacity = '';
            modal.style.transform = '';
        }
    };

    // ===== THEME TOGGLE LOGIC =====
    const themeToggle = document.getElementById('theme-toggle');
    const htmlEl = document.documentElement;

    const applyTheme = (theme) => {
        htmlEl.setAttribute('data-theme', theme);
        if (themeToggle) themeToggle.checked = (theme === 'dark');
    };

    const savedTheme = localStorage.getItem('theme') || 'dark';
    applyTheme(savedTheme);

    if (themeToggle) {
        themeToggle.addEventListener('change', () => {
            const newTheme = themeToggle.checked ? 'dark' : 'light';
            applyTheme(newTheme);
            localStorage.setItem('theme', newTheme);
        });
    }

    // ===== DELETE FILE MODAL BUTTON HANDLER =====
    const confirmDeleteBtn = document.getElementById('confirm-delete-file-btn');
    if (confirmDeleteBtn) {
        confirmDeleteBtn.addEventListener('click', confirmDeleteFile);
    }

    // ===== LOAD INITIAL USER DATA =====
    try {
        cache.currentUser = await API.getUserProfile();
    } catch (error) {
        console.error('Failed to load user profile:', error);
        // User is redirected to login if not authenticated
        return;
    }

    // ===== LOAD MFA STATUS =====
    let mfaEnabled = false;
    try {
        const mfaStatus = await API.getMFAStatus();
        mfaEnabled = mfaStatus.mfa_enabled || false;
        console.log('MFA Status:', mfaEnabled);
    } catch (error) {
        console.error('Failed to load MFA status:', error);
    }

    // ===== UTILITY FUNCTIONS =====
    const getUserInitials = (user) => {
        if (!user) return '??';
        if (user.first_name && user.last_name) {
            return `${user.first_name[0]}${user.last_name[0]}`.toUpperCase();
        }
        return user.username.substring(0, 2).toUpperCase();
    };

    const encryptionIconHTML = `<span class="encryption-indicator" data-tooltip="End-to-end encrypted"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg></span>`;

    const createAvatar = (initials, size = '36px') => `<div class="avatar" style="width:${size}; height:${size}; font-size: calc(${size} / 2.2);">${initials}</div>`;

    // ===== LOADING STATE HELPER =====
    function showLoading(elementId) {
        const element = document.getElementById(elementId);
        if (element) {
            element.innerHTML = '<div class="loading-state"><p>Loading...</p><div class="spinner"></div></div>';
        }
    }

    function showError(elementId, message) {
        const element = document.getElementById(elementId);
        if (element) {
            element.innerHTML = `<div class="error-state"><p>Error: ${message}</p></div>`;
        }
    }

    // ===== CORE APP LOGIC =====
    const sidebar = document.getElementById('sidebar');
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const mobileNavToggle = document.getElementById('mobile-nav-toggle');
    const navItems = document.querySelectorAll('.sidebar-nav .nav-item, .sidebar-footer .nav-item');
    const pages = document.querySelectorAll('.page');

    const showPage = async (pageId) => {
        pages.forEach(page => page.classList.toggle('is-active', page.id === pageId));
        navItems.forEach(item => item.classList.toggle('active', item.dataset.page === pageId));
        document.body.classList.remove('nav-open');
        sidebar.classList.remove('open');

        // Load page-specific data
        switch(pageId) {
            case 'dashboard-page':
                await renderDashboard();
                break;
            case 'my-ideas-page':
                await renderAllIdeas();
                break;
            case 'teams-page':
                await renderTeams();
                break;
            case 'drive-page':
                await renderDrive();
                break;
            case 'messages-page':
                // Use messages.js rendering if available
                if (typeof window.renderConversationList === 'function') {
                    await window.renderConversationList();
                }
                // Hide chat view, show placeholder
                const chatView = document.getElementById('chat-view');
                const chatPlaceholder = document.getElementById('chat-placeholder');
                if (chatView) chatView.classList.add('hidden');
                if (chatPlaceholder) chatPlaceholder.classList.remove('hidden');
                break;
        }
    };

    navItems.forEach(item => item.addEventListener('click', async (e) => {
        const pageId = item.dataset.page;
        // Don't prevent default for logout link (it needs to navigate to /logout)
        if (pageId) {
            e.preventDefault();
            await showPage(pageId);
        }
    }));

    if (sidebarToggle) sidebarToggle.addEventListener('click', () => sidebar.classList.toggle('collapsed'));
    if (mobileNavToggle) {
        mobileNavToggle.addEventListener('click', () => {
            document.body.classList.toggle('nav-open');
            sidebar.classList.toggle('open');
        });
    }

    document.body.addEventListener('click', (e) => {
        if (e.target.tagName === 'BODY' && document.body.classList.contains('nav-open')) {
            document.body.classList.remove('nav-open');
            sidebar.classList.remove('open');
        }
    });

    // ===== AI STUDIO TABS =====
    const studioTabs = document.querySelectorAll('.studio-tab');
    const studioContents = document.querySelectorAll('.studio-content');

    studioTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const targetTab = tab.dataset.tab;

            studioTabs.forEach(t => t.classList.remove('active'));
            studioContents.forEach(c => c.classList.remove('active'));

            tab.classList.add('active');
            document.getElementById(`${targetTab}-studio`).classList.add('active');
        });
    });

    // ===== MFA MODAL LOGIC (SECURE) =====
    const mfaToggle = document.getElementById('mfa-toggle-checkbox');
    const mfaModalOverlay = document.getElementById('mfa-modal-overlay');
    const mfaModal = document.getElementById('mfa-setup-modal');
    const closeMfaModal = document.getElementById('close-mfa-modal');
    const mfaNextBtn = document.getElementById('mfa-next-btn');
    const mfaPrevBtn = document.getElementById('mfa-prev-btn');
    const mfaFinishBtn = document.getElementById('mfa-finish-btn');
    let currentMfaStep = 1;
    let mfaSecretKey = null;  // Store secret key for the session

    const showMfaStep = (step) => {
        document.querySelectorAll('.mfa-step').forEach((s, i) => {
            s.classList.toggle('active', i + 1 === step);
        });
        document.querySelectorAll('.step-dot').forEach((dot, i) => {
            dot.classList.toggle('active', i + 1 === step);
        });

        mfaPrevBtn.style.display = step > 1 ? 'inline-flex' : 'none';
        mfaNextBtn.style.display = step < 3 ? 'inline-flex' : 'none';
        mfaFinishBtn.style.display = step === 3 ? 'inline-flex' : 'none';
    };

    if (mfaToggle) {
        // Set initial toggle state based on MFA status
        mfaToggle.checked = mfaEnabled;

        mfaToggle.addEventListener('change', async () => {
            if (mfaToggle.checked) {
                // Check if MFA is already enabled
                if (mfaEnabled) {
                    // MFA already enabled - prevent modal from opening
                    showFlash('MFA is already enabled on your account', 'info', 3000);
                    return;
                }

                // User wants to enable MFA - start setup flow
                try {
                    // Step 1: Call backend to generate QR code and secret
                    showFlash('Generating MFA setup...', 'info', 2000);
                    const setupData = await API.setupMFA();

                    // Store secret key
                    mfaSecretKey = setupData.secret_key;

                    // Update Step 2 with QR code and secret
                    const qrCodeContainer = document.querySelector('.qr-code-placeholder');
                    if (qrCodeContainer && setupData.qr_code_base64) {
                        qrCodeContainer.innerHTML = `<img src="data:image/png;base64,${setupData.qr_code_base64}" alt="QR Code" style="width: 200px; height: 200px;">`;
                    }

                    const secretKeyElement = document.querySelector('.mfa-secret-key code');
                    if (secretKeyElement && setupData.secret_key) {
                        // Format secret key with dashes for readability
                        const formattedKey = setupData.secret_key.match(/.{1,4}/g)?.join('-') || setupData.secret_key;
                        secretKeyElement.textContent = formattedKey;
                    }

                    // Show modal at step 1
                    currentMfaStep = 1;
                    showMfaStep(1);
                    mfaModalOverlay.classList.add('active');
                    mfaModal.classList.add('active');

                } catch (error) {
                    console.error('MFA setup error:', error);
                    showFlash('Failed to initialize MFA setup: ' + error.message, 'error');
                    mfaToggle.checked = false;
                }
            } else {
                // User wants to disable MFA
                if (mfaEnabled) {
                    // MFA is enabled - prevent disabling via toggle
                    showFlash('To disable MFA, please contact support', 'info', 3000);
                    mfaToggle.checked = true;  // Keep it checked
                }
            }
        });
    }

    if (closeMfaModal) {
        closeMfaModal.addEventListener('click', () => {
            mfaModalOverlay.classList.remove('active');
            mfaModal.classList.remove('active');
            if (mfaToggle) mfaToggle.checked = false;
            // Clear MFA code input
            const mfaCodeInput = document.getElementById('mfa-code');
            if (mfaCodeInput) mfaCodeInput.value = '';
        });
    }

    if (mfaNextBtn) {
        mfaNextBtn.addEventListener('click', () => {
            if (currentMfaStep < 3) {
                currentMfaStep++;
                showMfaStep(currentMfaStep);
            }
        });
    }

    if (mfaPrevBtn) {
        mfaPrevBtn.addEventListener('click', () => {
            if (currentMfaStep > 1) {
                currentMfaStep--;
                showMfaStep(currentMfaStep);
            }
        });
    }

    // Add input filter to MFA code field - only allow digits
    const mfaCodeInput = document.getElementById('mfa-code');
    if (mfaCodeInput) {
        mfaCodeInput.addEventListener('input', (e) => {
            // Remove any non-digit characters
            e.target.value = e.target.value.replace(/\D/g, '');

            // Limit to 6 digits
            if (e.target.value.length > 6) {
                e.target.value = e.target.value.slice(0, 6);
            }
        });

        // Prevent paste of non-numeric content
        mfaCodeInput.addEventListener('paste', (e) => {
            e.preventDefault();
            const pastedText = (e.clipboardData || window.clipboardData).getData('text');
            const digitsOnly = pastedText.replace(/\D/g, '').slice(0, 6);
            e.target.value = digitsOnly;
        });
    }

    if (mfaFinishBtn) {
        mfaFinishBtn.addEventListener('click', async () => {
            const codeInput = document.getElementById('mfa-code');
            const code = codeInput.value.trim();

            // Client-side validation (6 digits only)
            if (!/^\d{6}$/.test(code)) {
                showFlash('Please enter exactly 6 digits', 'error', 5000);
                return;
            }

            try {
                // Disable button during request
                mfaFinishBtn.disabled = true;
                mfaFinishBtn.textContent = 'Verifying...';

                // Call backend to verify code and enable MFA
                const result = await API.enableMFA(code);

                // Success! Close modal silently and reload page to refresh MFA status
                mfaModalOverlay.classList.remove('active');
                mfaModal.classList.remove('active');
                codeInput.value = '';
                mfaSecretKey = null;

                // Reload page to update MFA status (no flash message)
                setTimeout(() => {
                    window.location.reload();
                }, 500);

            } catch (error) {
                console.error('MFA enable error:', error);

                // Handle specific errors - ONLY show errors, not success
                let errorMessage = 'Failed to enable MFA';

                if (error.message.includes('Invalid MFA code') || error.message.includes('check your authenticator')) {
                    errorMessage = 'Incorrect code. Please check your authenticator app and try again.';
                } else if (error.message.includes('format') || error.message.includes('6 digits')) {
                    errorMessage = 'Invalid code format. Please enter exactly 6 digits.';
                } else if (error.message.includes('malicious') || error.message.includes('Suspicious')) {
                    errorMessage = 'Invalid characters detected. Please enter only digits.';
                } else if (error.message.includes('429') || error.message.includes('rate limit')) {
                    errorMessage = 'Too many attempts. Please wait a few minutes and try again.';
                } else if (error.message.includes('401')) {
                    errorMessage = 'Session expired. Please refresh the page and try again.';
                } else if (error.message) {
                    errorMessage = error.message;
                }

                showFlash(errorMessage, 'error', 7000);
            } finally {
                // Re-enable button
                mfaFinishBtn.disabled = false;
                mfaFinishBtn.textContent = 'Enable MFA';
            }
        });
    }

    mfaModalOverlay.addEventListener('click', (e) => {
        if (e.target === mfaModalOverlay) {
            mfaModalOverlay.classList.remove('active');
            mfaModal.classList.remove('active');
            if (mfaToggle) mfaToggle.checked = false;
            // Clear MFA code input
            const mfaCodeInput = document.getElementById('mfa-code');
            if (mfaCodeInput) mfaCodeInput.value = '';
        }
    });

    // ===== AI GENERATION FORM HANDLERS =====
    const imageForm = document.getElementById('image-form');
    const videoForm = document.getElementById('video-form');
    const voiceForm = document.getElementById('voice-form');

    if (imageForm) {
        const submitBtn = imageForm.querySelector('button[type="submit"]');
        const originalBtnText = submitBtn.innerHTML;

        imageForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            // Collect form data
            const formData = {
                prompt: document.getElementById('image-prompt').value.trim(),
                style: document.getElementById('image-style').value,
                aspect_ratio: document.getElementById('image-ratio').value
            };

            // Validate required fields
            if (!formData.prompt) {
                showFlash('Please enter an image prompt', 'error');
                return;
            }

            if (formData.prompt.length < 10) {
                showFlash('Image prompt must be at least 10 characters', 'error');
                return;
            }

            // Show progress modal
            showImageProgressModal();

            try {
                console.log('🎨 Generating image with Flux AI...', formData);

                // Call Flux API
                const result = await API.generateImage(formData);

                if (result.success) {
                    // Show success in modal with image
                    showImageSuccess(result.image);

                    // Reset form
                    imageForm.reset();

                    // Log metadata
                    console.log('✅ Image generated:', {
                        id: result.image.id,
                        url: result.image.image_url,
                        style: result.image.style,
                        aspect_ratio: result.image.aspect_ratio
                    });
                } else {
                    showImageError('Image generation failed');
                }
            } catch (error) {
                console.error('❌ Image generation error:', error);
                showImageError(error.message || 'Failed to generate image');
            }
        });

        // Image Progress Modal Functions
        function showImageProgressModal() {
            console.log('📢 showImageProgressModal called');
            const modalOverlay = document.getElementById('image-progress-modal-overlay');
            const modal = document.getElementById('image-progress-modal');
            console.log('📢 Modal overlay element:', modalOverlay ? 'Found' : 'NOT FOUND');
            console.log('📢 Modal element:', modal ? 'Found' : 'NOT FOUND');

            if (modalOverlay && modal) {
                console.log('📢 Adding active class and setting displays');
                // Add active class to trigger CSS animations
                modalOverlay.classList.add('active');
                modalOverlay.style.display = 'grid';

                // Show the modal content
                modal.style.display = 'block';
                modal.style.opacity = '1';
                modal.style.transform = 'scale(1)';

                // Show/hide content sections
                document.getElementById('image-generating-content').style.display = 'block';
                document.getElementById('image-success-content').style.display = 'none';
                document.getElementById('image-error-content').style.display = 'none';
                console.log('📢 Modal should now be visible');
            } else {
                console.error('❌ Modal element(s) not found!');
            }
        }

        function showImageSuccess(imageData) {
            console.log('📢 showImageSuccess called with:', imageData);

            // Ensure modal overlay and modal are visible
            const modalOverlay = document.getElementById('image-progress-modal-overlay');
            const modal = document.getElementById('image-progress-modal');
            if (!modalOverlay || !modal) {
                console.error('❌ Image modal overlay or modal not found!');
                return;
            }
            modalOverlay.classList.add('active');
            modal.classList.add('active');

            // Hide generating content
            const generatingContent = document.getElementById('image-generating-content');
            console.log('🔍 Generating content element:', generatingContent);
            if (generatingContent) {
                generatingContent.style.display = 'none';
                console.log('✅ Hiding generating content');
            } else {
                console.error('❌ Generating content element not found!');
            }

            // Hide error content
            const errorContent = document.getElementById('image-error-content');
            if (errorContent) {
                errorContent.style.display = 'none';
            }

            // Show success content
            const successContent = document.getElementById('image-success-content');
            console.log('🔍 Success content element:', successContent);
            console.log('🔍 Current display value:', successContent ? successContent.style.display : 'N/A');
            if (successContent) {
                successContent.style.display = 'block';
                console.log('✅ Set success content display to block');
                console.log('🔍 New display value:', successContent.style.display);
                // Force visibility
                successContent.style.visibility = 'visible';
                successContent.style.opacity = '1';
            } else {
                console.error('❌ Success content element not found!');
            }

            // Set image preview
            const imagePreview = document.getElementById('image-preview');
            console.log('🔍 Image preview element:', imagePreview);
            if (imagePreview) {
                imagePreview.src = imageData.image_url;
                console.log('✅ Image preview src set to:', imageData.image_url);
            } else {
                console.error('❌ Image preview element not found!');
            }

            console.log('📢 Success content transition complete');
        }

        function showImageError(errorMessage) {
            console.log('❌ Showing image error modal:', errorMessage);

            // Ensure modal overlay and modal are visible
            const modalOverlay = document.getElementById('image-progress-modal-overlay');
            const modal = document.getElementById('image-progress-modal');
            if (!modalOverlay || !modal) {
                console.error('❌ Image modal overlay or modal not found!');
                return;
            }
            modalOverlay.classList.add('active');
            modal.classList.add('active');

            // Hide generating content
            const generatingContent = document.getElementById('image-generating-content');
            if (generatingContent) {
                generatingContent.style.display = 'none';
            }

            // Hide success content
            const successContent = document.getElementById('image-success-content');
            if (successContent) {
                successContent.style.display = 'none';
            }

            // Show error content
            const errorContent = document.getElementById('image-error-content');
            if (errorContent) {
                errorContent.style.display = 'block';
            }

            // Update error message
            const errorMessageEl = document.getElementById('image-error-message');
            if (errorMessageEl) {
                errorMessageEl.textContent = errorMessage;
            }
        }

        // Make close function global so modal button can access it
        window.closeImageModal = function() {
            console.log('📢 closeImageModal called');
            const modalOverlay = document.getElementById('image-progress-modal-overlay');
            const modal = document.getElementById('image-progress-modal');

            if (modalOverlay && modal) {
                // Remove active class to trigger CSS animations
                modalOverlay.classList.remove('active');
                modal.classList.remove('active');

                // Hide the modal by setting display to none
                modalOverlay.style.display = 'none';
                modal.style.display = 'none';

                // Reset modal state for next use
                const generatingContent = document.getElementById('image-generating-content');
                const successContent = document.getElementById('image-success-content');
                const errorContent = document.getElementById('image-error-content');

                if (generatingContent) generatingContent.style.display = 'block';
                if (successContent) successContent.style.display = 'none';
                if (errorContent) errorContent.style.display = 'none';

                console.log('📢 Modal closed successfully - display set to none');
            }
        };
    }

    // Video Generation Form with Progress Modal
    if (videoForm) {
        const submitBtn = videoForm.querySelector('button[type="submit"]');
        const originalBtnText = submitBtn.innerHTML;
        let videoPollingInterval = null;
        let currentVideoIdeaId = null;

        videoForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            // Collect form data
            const formData = {
                prompt: document.getElementById('video-prompt').value.trim(),
                duration: parseInt(document.getElementById('video-duration').value),
                aspect_ratio: document.getElementById('video-aspect-ratio').value,
                cfg_scale: parseFloat(document.getElementById('video-cfg-scale').value),
                negative_prompt: document.getElementById('video-negative-prompt').value.trim() || null
            };

            // Validate required fields
            if (!formData.prompt) {
                showFlash('Please enter a video concept', 'error');
                return;
            }

            if (formData.prompt.length < 10) {
                showFlash('Video prompt must be at least 10 characters', 'error');
                return;
            }

            // Disable submit button and show loading state
            submitBtn.disabled = true;
            submitBtn.innerHTML = `
                <svg class="spinner" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M21 12a9 9 0 1 1-6.219-8.56"></path>
                </svg>
                Starting...
            `;

            try {
                console.log('🎬 Starting video generation with Kling AI...', formData);

                // Call Video Generation API
                const response = await fetch('/api/v1/ideas/generate-video', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${localStorage.getItem('session_token')}`,
                        'X-CSRF-Token': API.getCSRFToken()
                    },
                    body: JSON.stringify(formData)
                });

                const result = await response.json();

                if (response.status === 429) {
                    showFlash('Rate limit exceeded. Please try again in an hour.', 'error');
                    return;
                }

                if (!response.ok) {
                    showFlash(result.detail || 'Failed to start video generation', 'error');
                    return;
                }

                // Success - show modal and start polling
                currentVideoIdeaId = result.idea_id;
                console.log('✅ Video generation started:', {
                    idea_id: result.idea_id,
                    task_id: result.task_id,
                    estimated_time: result.estimated_time
                });

                // Show progress modal
                showVideoProgressModal();

                // Reset form
                videoForm.reset();

                // Start polling for status every 5 seconds
                videoPollingInterval = setInterval(() => {
                    pollVideoStatus(currentVideoIdeaId);
                }, 5000);

                // Initial poll
                pollVideoStatus(currentVideoIdeaId);

            } catch (error) {
                console.error('❌ Video generation error:', error);
                showFlash(error.message || 'Failed to start video generation', 'error');
            } finally {
                // Re-enable submit button
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalBtnText;
            }
        });

        // Video Progress Modal Functions
        function showVideoProgressModal() {
            const modalOverlay = document.getElementById('video-progress-modal-overlay');
            const modalContent = document.getElementById('video-progress-modal');
            if (modalOverlay && modalContent) {
                modalOverlay.classList.add('active');
                modalContent.classList.add('active');
                modalOverlay.style.display = 'flex';

                // Reset to initial state
                document.getElementById('video-generating-content').style.display = 'block';
                document.getElementById('video-success-content').style.display = 'none';
                document.getElementById('video-error-content').style.display = 'none';
                document.getElementById('video-progress-bar').style.width = '0%';
                document.getElementById('video-progress-percent').textContent = '0%';
                document.getElementById('video-status-text').textContent = 'Starting video generation...';
            }
        }

        function closeVideoProgressModal() {
            const modalOverlay = document.getElementById('video-progress-modal-overlay');
            const modalContent = document.getElementById('video-progress-modal');
            if (modalOverlay && modalContent) {
                modalOverlay.classList.remove('active');
                modalContent.classList.remove('active');

                // Hide the modal by setting display to none
                modalOverlay.style.display = 'none';
                modalContent.style.display = 'none';

                // Reset modal state for next use
                const generatingContent = document.getElementById('video-generating-content');
                const successContent = document.getElementById('video-success-content');
                const errorContent = document.getElementById('video-error-content');

                if (generatingContent) generatingContent.style.display = 'block';
                if (successContent) successContent.style.display = 'none';
                if (errorContent) errorContent.style.display = 'none';
            }
            if (videoPollingInterval) {
                clearInterval(videoPollingInterval);
                videoPollingInterval = null;
            }
            currentVideoIdeaId = null;
        }

        // Make close function global so modal button can access it
        window.closeVideoModal = closeVideoProgressModal;

        async function pollVideoStatus(ideaId) {
            try {
                const response = await fetch(`/api/v1/ideas/video-status/${ideaId}`, {
                    headers: {
                        'Authorization': `Bearer ${localStorage.getItem('session_token')}`
                    }
                });

                if (!response.ok) {
                    throw new Error('Failed to check video status');
                }

                const data = await response.json();
                console.log('📊 Video status:', data);

                if (data.status === 'completed') {
                    // Video is ready!
                    clearInterval(videoPollingInterval);
                    videoPollingInterval = null;

                    // Ensure modal is still visible
                    const modalOverlay = document.getElementById('video-progress-modal-overlay');
                    const modal = document.getElementById('video-progress-modal');
                    if (modalOverlay && modal) {
                        modalOverlay.classList.add('active');
                        modal.classList.add('active');
                    }

                    document.getElementById('video-generating-content').style.display = 'none';
                    document.getElementById('video-success-content').style.display = 'block';
                    document.getElementById('video-progress-bar').style.width = '100%';
                    document.getElementById('video-progress-percent').textContent = '100%';

                    console.log('✅ Video generation completed!', {
                        video_url: data.video_url,
                        duration: data.duration,
                        aspect_ratio: data.aspect_ratio
                    });

                } else if (data.status === 'failed' || data.status === 'error') {
                    // Video generation failed
                    clearInterval(videoPollingInterval);
                    videoPollingInterval = null;

                    // Ensure modal is still visible
                    const modalOverlay = document.getElementById('video-progress-modal-overlay');
                    const modal = document.getElementById('video-progress-modal');
                    if (modalOverlay && modal) {
                        modalOverlay.classList.add('active');
                        modal.classList.add('active');
                    }

                    document.getElementById('video-generating-content').style.display = 'none';
                    document.getElementById('video-error-content').style.display = 'block';
                    document.getElementById('video-error-message').textContent =
                        data.error || 'Video generation failed. Please try again.';

                    console.error('❌ Video generation failed:', data.error);

                } else if (data.status === 'processing') {
                    // Still processing - update progress
                    const progress = data.progress || 0;
                    document.getElementById('video-progress-bar').style.width = progress + '%';
                    document.getElementById('video-progress-percent').textContent = progress + '%';

                    // Update status text based on progress
                    if (progress < 30) {
                        document.getElementById('video-status-text').textContent = 'Initializing video generation...';
                    } else if (progress < 70) {
                        document.getElementById('video-status-text').textContent = 'Generating video frames...';
                    } else {
                        document.getElementById('video-status-text').textContent = 'Finalizing video...';
                    }
                }

            } catch (error) {
                console.error('❌ Error polling video status:', error);
                // Continue polling on error (might be temporary network issue)
            }
        }
    }

    // Voice Generation Form
    if (voiceForm) {
        const submitBtn = voiceForm.querySelector('button[type="submit"]');
        const originalBtnText = submitBtn.innerHTML;

        voiceForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            // Collect form data
            const formData = {
                text: document.getElementById('voice-text').value.trim(),
                voice_type: document.getElementById('voice-type').value,
                model: 'standard',
                title: `Voice: ${document.getElementById('voice-type').value}`
            };

            // Validate required fields
            if (!formData.text) {
                showFlash('Please enter text to convert to speech', 'error');
                return;
            }

            if (formData.text.length > 5000) {
                showFlash('Text is too long (max 5000 characters)', 'error');
                return;
            }

            // Show progress modal
            showVoiceProgressModal();

            try {
                console.log('🎤 Generating voice...', formData);

                // Call Voice Generation API
                const response = await fetch('/api/v1/ideas/generate-voice', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${localStorage.getItem('session_token')}`,
                        'X-CSRF-Token': API.getCSRFToken()
                    },
                    body: JSON.stringify(formData)
                });

                const result = await response.json();

                if (response.ok && result.success) {
                    // Show success in modal
                    showVoiceSuccess();

                    // Reset form
                    voiceForm.reset();

                    console.log('✅ Voice generated:', result.voice);
                } else {
                    const errorMsg = result.detail || result.error || 'Failed to generate voice';
                    showVoiceError(errorMsg);
                    console.error('❌ Voice generation error:', errorMsg);
                }
            } catch (error) {
                console.error('❌ Voice generation error:', error);
                showVoiceError('Failed to generate voice. Please try again.');
            }
        });

        // Voice Progress Modal Functions
        function showVoiceProgressModal() {
            console.log('🎤 Opening voice progress modal...');
            const modalOverlay = document.getElementById('voice-progress-modal-overlay');
            const modal = document.getElementById('voice-progress-modal');
            if (modalOverlay && modal) {
                modalOverlay.classList.add('active');
                modal.classList.add('active');
                document.getElementById('voice-generating-content').style.display = 'block';
                document.getElementById('voice-success-content').style.display = 'none';
                document.getElementById('voice-error-content').style.display = 'none';
            } else {
                console.error('❌ Voice modal overlay or modal not found!');
            }
        }

        function showVoiceSuccess() {
            console.log('✅ Showing voice success modal...');

            // Ensure modal overlay and modal are visible
            const modalOverlay = document.getElementById('voice-progress-modal-overlay');
            const modal = document.getElementById('voice-progress-modal');
            if (!modalOverlay || !modal) {
                console.error('❌ Voice modal overlay or modal not found!');
                return;
            }
            modalOverlay.classList.add('active');
            modal.classList.add('active');

            // Hide generating content
            const generatingContent = document.getElementById('voice-generating-content');
            if (generatingContent) {
                generatingContent.style.display = 'none';
            }

            // Hide error content
            const errorContent = document.getElementById('voice-error-content');
            if (errorContent) {
                errorContent.style.display = 'none';
            }

            // Show success content
            const successContent = document.getElementById('voice-success-content');
            if (successContent) {
                successContent.style.display = 'block';
            } else {
                console.error('❌ Voice success content not found!');
            }

            console.log('✅ Voice modal switched to success view');
        }

        function showVoiceError(errorMessage) {
            console.log('❌ Showing voice error modal:', errorMessage);

            // Ensure modal overlay and modal are visible
            const modalOverlay = document.getElementById('voice-progress-modal-overlay');
            const modal = document.getElementById('voice-progress-modal');
            if (!modalOverlay || !modal) {
                console.error('❌ Voice modal overlay or modal not found!');
                return;
            }
            modalOverlay.classList.add('active');
            modal.classList.add('active');

            // Hide generating content
            const generatingContent = document.getElementById('voice-generating-content');
            if (generatingContent) {
                generatingContent.style.display = 'none';
            }

            // Hide success content
            const successContent = document.getElementById('voice-success-content');
            if (successContent) {
                successContent.style.display = 'none';
            }

            // Show error content
            const errorContent = document.getElementById('voice-error-content');
            if (!errorContent) {
                console.error('❌ Voice error content not found!');
                return;
            }
            errorContent.style.display = 'block';

            // Update error message
            const errorMessageEl = document.getElementById('voice-error-message');
            if (errorMessageEl) {
                errorMessageEl.textContent = errorMessage;
            } else {
                console.error('❌ Voice error message element not found!');
            }

            console.log('✅ Voice modal switched to error view');
        }

        // Make close function global so modal button can access it
        window.closeVoiceModal = function() {
            const modalOverlay = document.getElementById('voice-progress-modal-overlay');
            const modal = document.getElementById('voice-progress-modal');

            if (modalOverlay) {
                modalOverlay.classList.remove('active');
                modalOverlay.style.display = 'none';
            }
            if (modal) {
                modal.classList.remove('active');
                modal.style.display = 'none';
            }

            // Reset modal state for next use
            const generatingContent = document.getElementById('voice-generating-content');
            const successContent = document.getElementById('voice-success-content');
            const errorContent = document.getElementById('voice-error-content');

            if (generatingContent) generatingContent.style.display = 'block';
            if (successContent) successContent.style.display = 'none';
            if (errorContent) errorContent.style.display = 'none';
        };
    }

    // GPT5 Script Generation Form
    const ideaForm = document.getElementById('idea-form');
    if (ideaForm) {
        const submitBtn = ideaForm.querySelector('button[type="submit"]');
        const originalBtnText = submitBtn.innerHTML;

        ideaForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            // Collect form data
            const formData = {
                title: document.getElementById('project-title').value.trim(),
                description: document.getElementById('project-description').value.trim() || '',
                content_type: document.getElementById('project-type').value,
                brand_voice: document.getElementById('brand-voice').value.trim() || '',
                target_audience: document.getElementById('target-audience').value.trim(),
                key_messages: document.getElementById('key-messages').value.trim()
            };

            // Validate required fields
            if (!formData.title || !formData.content_type || !formData.target_audience || !formData.key_messages) {
                showFlash('Please fill in all required fields', 'error');
                return;
            }

            // Validate minimum lengths
            if (formData.title.length < 3) {
                showFlash('Title must be at least 3 characters long', 'error');
                return;
            }
            if (formData.target_audience.length < 10) {
                showFlash('Target Audience must be at least 10 characters long', 'error');
                return;
            }
            if (formData.key_messages.length < 10) {
                showFlash('Key Messages must be at least 10 characters long', 'error');
                return;
            }

            // Show progress modal
            showScriptProgressModal();

            try {
                console.log('🚀 Generating script with GPT-5...', formData);

                // Call GPT5 API
                const result = await API.generateScript(formData);

                console.log('📥 API Response:', result);
                console.log('✅ Success flag:', result.success);
                console.log('📝 Idea content:', result.idea);

                if (result && result.success) {
                    // Show success in modal with script content
                    console.log('✨ Showing success modal...');
                    showScriptSuccess(result.idea.content);

                    // Reset form
                    ideaForm.reset();

                    // Refresh ideas cache
                    cache.lastFetch.ideas = 0;

                    // Log metadata
                    console.log('✅ Script generated:', {
                        id: result.idea.id,
                        words: result.metadata?.word_count || 'N/A',
                        tokens: result.metadata?.total_tokens || 'N/A'
                    });
                } else {
                    console.log('⚠️ Result missing success flag');
                    throw new Error(result.message || 'Script generation failed');
                }
            } catch (error) {
                console.error('❌ Script generation error:', error);
                console.error('❌ Error details:', error.message, error.stack);
                showScriptError(error.message || 'Failed to generate script');
            }
        });

        // Script Progress Modal Functions
        function showScriptProgressModal() {
            console.log('📋 Opening progress modal...');
            const modalOverlay = document.getElementById('script-progress-modal-overlay');
            const modal = document.getElementById('script-progress-modal');
            console.log('Modal overlay element:', modalOverlay);
            if (modalOverlay && modal) {
                modalOverlay.classList.add('active');
                modal.classList.add('active');
                document.getElementById('script-generating-content').style.display = 'block';
                document.getElementById('script-success-content').style.display = 'none';
                document.getElementById('script-error-content').style.display = 'none';
            } else {
                console.error('❌ Modal overlay or modal not found!');
            }
        }

        function showScriptSuccess(scriptContent) {
            console.log('🎉 showScriptSuccess called with content length:', scriptContent?.length);

            // Ensure modal overlay and modal are visible
            const modalOverlay = document.getElementById('script-progress-modal-overlay');
            const modal = document.getElementById('script-progress-modal');
            if (!modalOverlay || !modal) {
                console.error('❌ Modal overlay or modal not found!');
                return;
            }
            modalOverlay.classList.add('active');
            modal.classList.add('active');

            // Hide generating content
            const generatingContent = document.getElementById('script-generating-content');
            if (generatingContent) {
                generatingContent.style.display = 'none';
            }

            // Hide error content
            const errorContent = document.getElementById('script-error-content');
            if (errorContent) {
                errorContent.style.display = 'none';
            }

            // Show success content
            const successContent = document.getElementById('script-success-content');
            if (!successContent) {
                console.error('❌ Success content element not found!');
                return;
            }
            successContent.style.display = 'block';

            // Update script preview
            const scriptPreview = document.getElementById('script-preview');
            if (scriptPreview) {
                scriptPreview.textContent = scriptContent;
            } else {
                console.error('❌ Script preview element not found!');
            }

            console.log('✅ Modal switched to success view');
        }

        function showScriptError(errorMessage) {
            console.log('❌ showScriptError called with:', errorMessage);

            // Ensure modal overlay and modal are visible
            const modalOverlay = document.getElementById('script-progress-modal-overlay');
            const modal = document.getElementById('script-progress-modal');
            if (!modalOverlay || !modal) {
                console.error('❌ Modal overlay or modal not found!');
                return;
            }
            modalOverlay.classList.add('active');
            modal.classList.add('active');

            // Hide generating content
            const generatingContent = document.getElementById('script-generating-content');
            if (generatingContent) {
                generatingContent.style.display = 'none';
            }

            // Hide success content
            const successContent = document.getElementById('script-success-content');
            if (successContent) {
                successContent.style.display = 'none';
            }

            // Show error content
            const errorContent = document.getElementById('script-error-content');
            if (!errorContent) {
                console.error('❌ Error content element not found!');
                return;
            }
            errorContent.style.display = 'block';

            // Update error message
            const errorMessageEl = document.getElementById('script-error-message');
            if (errorMessageEl) {
                errorMessageEl.textContent = errorMessage;
            } else {
                console.error('❌ Error message element not found!');
            }

            console.log('✅ Modal switched to error view');
        }

        // Make close function global so modal button can access it
        window.closeScriptModal = function() {
            const modalOverlay = document.getElementById('script-progress-modal-overlay');
            const modal = document.getElementById('script-progress-modal');

            if (modalOverlay) {
                modalOverlay.classList.remove('active');
                modalOverlay.style.display = 'none';
            }
            if (modal) {
                modal.classList.remove('active');
                modal.style.display = 'none';
            }

            // Reset modal state for next use
            const generatingContent = document.getElementById('script-generating-content');
            const successContent = document.getElementById('script-success-content');
            const errorContent = document.getElementById('script-error-content');

            if (generatingContent) generatingContent.style.display = 'block';
            if (successContent) successContent.style.display = 'none';
            if (errorContent) errorContent.style.display = 'none';
        };

        // Make loadMyIdeas function global for modal button
        window.loadMyIdeas = function() {
            // Switch to My Ideas tab and refresh data
            const myIdeasTab = document.querySelector('[data-tab="my-ideas"]');
            if (myIdeasTab) {
                myIdeasTab.click();
            }
            // Force cache refresh
            cache.lastFetch.ideas = 0;
        };

        // Cancel button
        const cancelBtn = document.getElementById('idea-cancel-btn');
        if (cancelBtn) {
            cancelBtn.addEventListener('click', () => {
                ideaForm.reset();
                showFlash('Form cleared', 'info');
            });
        }
    }

    // ===== DYNAMIC RENDERING FUNCTIONS =====

    const renderDashboard = async () => {
        const statsGrid = document.getElementById('stats-grid');
        if (!statsGrid) return;

        try {
            showLoading('stats-grid');

            // Fetch ideas
            if (shouldRefreshCache('ideas')) {
                const ideasData = await API.getIdeas();
                updateCache('ideas', ideasData.ideas || []);
            }

            const ideas = cache.ideas;
            const activeIdeas = ideas.filter(i => i.status !== 'archived' && !i.is_deleted);
            const inProgressCount = activeIdeas.filter(i => i.status === 'in_progress').length;
            const completedCount = activeIdeas.filter(i => i.status === 'completed').length;
            const inReviewCount = activeIdeas.filter(i => i.status === 'review').length;

            statsGrid.innerHTML = `
                <div class="stat-card card"><div class="stat-card-icon"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg></div><div class="stat-card-info"><h3>Active Ideas</h3><p class="stat-number">${activeIdeas.length}</p></div></div>
                <div class="stat-card card"><div class="stat-card-icon"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z"></path><polyline points="12 6 12 12 16 14"></polyline></svg></div><div class="stat-card-info"><h3>In Progress</h3><p class="stat-number">${inProgressCount}</p></div></div>
                <div class="stat-card card"><div class="stat-card-icon"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 6.5A3.5 3.5 0 0 0 8.5 3A3.5 3.5 0 0 0 5 6.5a3.5 3.5 0 0 0 3.5 3.5h2a3.5 3.5 0 0 0 3.5-3.5zM15 17.5a3.5 3.5 0 0 0-3.5 3.5a3.5 3.5 0 0 0 3.5 3.5a3.5 3.5 0 0 0 3.5-3.5a3.5 3.5 0 0 0-3.5-3.5zM8.5 14A3.5 3.5 0 0 0 5 17.5A3.5 3.5 0 0 0 8.5 21H12v-2.5a3.5 3.5 0 0 0-3.5-3.5z"/></svg></div><div class="stat-card-info"><h3>In Review</h3><p class="stat-number">${inReviewCount}</p></div></div>
                <div class="stat-card card"><div class="stat-card-icon"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg></div><div class="stat-card-info"><h3>Completed</h3><p class="stat-number">${completedCount}</p></div></div>`;

            const recentIdeasList = document.getElementById('recent-ideas-list');
            if (!recentIdeasList) return;

            const sortedIdeas = activeIdeas.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
            recentIdeasList.innerHTML = sortedIdeas.length === 0
                ? `<p>No recent ideas. Time to create something new!</p>`
                : sortedIdeas.slice(0, 3).map(idea => {
                    // Determine icon based on content type
                    let ideaIcon = encryptionIconHTML; // Default (document icon for scripts)

                    if (idea.content_type === 'image' || idea.has_image) {
                        ideaIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>`;
                    } else if (idea.content_type === 'voice' || idea.has_voice) {
                        ideaIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"></path><path d="M19 10v2a7 7 0 0 1-14 0v-2"></path><line x1="12" y1="19" x2="12" y2="23"></line><line x1="8" y1="23" x2="16" y2="23"></line></svg>`;
                    } else if (idea.video_url || idea.video_status) {
                        ideaIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="23 7 16 12 23 17 23 7"></polygon><rect x="1" y="5" width="15" height="14" rx="2" ry="2"></rect></svg>`;
                    }

                    return `
                    <div class="idea-item" data-idea-id="${idea.id}" style="cursor: pointer;">
                        <div class="idea-item-info">
                            ${ideaIcon}
                            <div class="idea-item-details">
                                <h4>${escapeHtml(idea.title)}</h4>
                                <p>Created: ${new Date(idea.created_at).toLocaleDateString()}</p>
                            </div>
                        </div>
                        <span class="status-badge status-${idea.status.replace('_', '-')}">${idea.status.replace('_', ' ')}</span>
                    </div>`;
                }).join('');

        } catch (error) {
            showError('stats-grid', 'Failed to load dashboard data');
            console.error('Dashboard render error:', error);
        }
    };

    const renderAllIdeas = async () => {
        const tbody = document.getElementById('all-ideas-tbody');
        if (!tbody) return;

        try {
            showLoading('all-ideas-tbody');

            // Always fetch fresh data for My Ideas page (ignore cache)
            console.log('🔄 Fetching fresh ideas and images...');
            const myIdeasData = await API.getMyIdeas(50, 0);
            const teamIdeasData = await API.getTeamIdeas(50, 0);

            // Debug: Log the fetched data
            console.log('My Ideas Data:', myIdeasData);
            console.log('Team Ideas Data:', teamIdeasData);

            // Debug: Log raw idea objects
            if (myIdeasData.ideas && myIdeasData.ideas.length > 0) {
                console.log('First idea object keys:', Object.keys(myIdeasData.ideas[0]));
                console.log('First idea raw:', JSON.stringify(myIdeasData.ideas[0], null, 2));
            }

            // Debug: Log images
            if (myIdeasData.images && myIdeasData.images.length > 0) {
                console.log('📷 Images found:', myIdeasData.images.length);
                console.log('First image:', JSON.stringify(myIdeasData.images[0], null, 2));
            }

            // Combine ideas, images, and team ideas
            const allIdeas = [
                ...(myIdeasData.ideas || []),
                ...(myIdeasData.images || []),  // Add images to the list
                ...(teamIdeasData.ideas || [])
            ];

            // Remove duplicates (in case user owns an idea that's also assigned to their team)
            // Use a better unique key: content_type + id to avoid collisions
            const uniqueIdeas = Array.from(
                new Map(allIdeas.map(idea => [`${idea.content_type || 'text'}_${idea.id}`, idea])).values()
            );

            // Debug: Log the combined ideas
            console.log('Combined Ideas (including images):', uniqueIdeas);

            // Update cache with fresh data
            updateCache('ideas', uniqueIdeas);

            // Use the fresh data (not from cache)
            const ideas = uniqueIdeas;

            // Debug: Log ideas before rendering
            console.log('Ideas to render:', ideas);

            tbody.innerHTML = ideas.length === 0
                ? `<tr><td colspan="7" style="text-align: center; padding: 2rem;">
                    <p style="color: #64748b; margin-bottom: 1rem;">You haven't created any AI scripts yet.</p>
                    <p style="color: #94a3b8; font-size: 0.9rem;">Click the "Create Idea" tab to generate your first script with GPT-5!</p>
                   </td></tr>`
                : ideas.map(idea => {
                    // Debug: Log each idea's team_name
                    console.log(`Idea ID ${idea.id}: team_name="${idea.team_name}", team_id="${idea.team_id}"`);

                    // Helper function to get status badge
                    const getStatusBadge = (status) => {
                        const statusColors = {
                            'draft': '#94a3b8',
                            'in_progress': '#3b82f6',
                            'review': '#f59e0b',
                            'completed': '#10b981'
                        };
                        const statusLabels = {
                            'draft': 'Draft',
                            'in_progress': 'In Progress',
                            'review': 'Review',
                            'completed': 'Completed'
                        };
                        const color = statusColors[status] || '#94a3b8';
                        const label = statusLabels[status] || status;
                        return `<span style="
                            display: inline-block;
                            padding: 0.25rem 0.75rem;
                            border-radius: 12px;
                            background-color: ${color}15;
                            color: ${color};
                            font-size: 0.85rem;
                            font-weight: 500;
                        ">${label}</span>`;
                    };

                    // Check if this is a team idea
                    const isTeamIdea = idea.team_name && !idea.is_owner;
                    const ownerBadge = isTeamIdea
                        ? `<span style="color: #ff7f50; font-size: 0.85rem;">by @${escapeHtml(idea.owner_username)}</span>`
                        : '';

                    // Determine content type icon
                    let contentType = idea.content_type || 'text';
                    let contentIcon = encryptionIconHTML;  // Default
                    let contentBadge = '';

                    if (contentType === 'image' && idea.has_image) {
                        contentIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>`;
                        contentBadge = `<span style="background: #10b98115; color: #10b981; padding: 0.2rem 0.5rem; border-radius: 6px; font-size: 0.75rem;">IMAGE</span>`;
                    } else if (contentType === 'voice' && idea.has_voice) {
                        contentIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"></path><path d="M19 10v2a7 7 0 0 1-14 0v-2"></path><line x1="12" y1="19" x2="12" y2="23"></line><line x1="8" y1="23" x2="16" y2="23"></line></svg>`;
                        contentBadge = `<span style="background: #10b98115; color: #10b981; padding: 0.2rem 0.5rem; border-radius: 6px; font-size: 0.75rem;">VOICE</span>`;
                    } else if (idea.video_url || idea.video_status) {
                        // Video content - override contentType
                        contentType = 'video';
                        contentIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="23 7 16 12 23 17 23 7"></polygon><rect x="1" y="5" width="15" height="14" rx="2" ry="2"></rect></svg>`;

                        if (idea.video_status === 'processing') {
                            contentBadge = `<span style="background: #3b82f615; color: #3b82f6; padding: 0.2rem 0.5rem; border-radius: 6px; font-size: 0.75rem;">VIDEO (Generating...)</span>`;
                        } else if (idea.video_status === 'completed') {
                            contentBadge = `<span style="background: #10b98115; color: #10b981; padding: 0.2rem 0.5rem; border-radius: 6px; font-size: 0.75rem;">VIDEO</span>`;
                        } else if (idea.video_status === 'failed') {
                            contentBadge = `<span style="background: #ef444415; color: #ef4444; padding: 0.2rem 0.5rem; border-radius: 6px; font-size: 0.75rem;">VIDEO (Failed)</span>`;
                        } else {
                            contentBadge = `<span style="background: #10b98115; color: #10b981; padding: 0.2rem 0.5rem; border-radius: 6px; font-size: 0.75rem;">VIDEO</span>`;
                        }
                    }

                    // Custom action buttons based on content type
                    // Only show "Assign to Team" button if user is the owner
                    const assignToTeamButton = idea.is_owner !== false ? `
                        <button class="assign-team-btn" title="Assign to Team" data-idea-id="${idea.id}">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="8.5" cy="7" r="4"></circle><polyline points="17 11 19 13 23 9"></polyline></svg>
                        </button>` : '';

                    let actionButtons = '';
                    if (contentType === 'image') {
                        actionButtons = `
                            ${assignToTeamButton}
                            <button class="view-image-btn" title="View Image" data-image-url="${idea.image_url}" data-idea-id="${idea.id}">
                                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                            </button>
                            <button class="download-image-btn" title="Download Image" data-image-url="${idea.image_url}">
                                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                            </button>`;
                    } else if (contentType === 'voice') {
                        actionButtons = `
                            ${assignToTeamButton}
                            <button class="play-voice-btn" title="Play Voice" data-idea-id="${idea.id}" data-voice-path="${idea.voice_file_path}">
                                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                            </button>
                            <button class="download-voice-btn" title="Download Voice" data-idea-id="${idea.id}">
                                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                            </button>`;
                    } else if (idea.video_url || idea.video_status) {
                        // Video buttons
                        if (idea.video_status === 'completed' && idea.video_url) {
                            actionButtons = `
                                ${assignToTeamButton}
                                <button class="play-video-btn" title="Play Video" data-idea-id="${idea.id}" data-video-url="${idea.video_url}">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                                </button>
                                <button class="download-video-btn" title="Download Video" data-video-url="${idea.video_url}">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                                </button>`;
                        } else if (idea.video_status === 'processing') {
                            actionButtons = `
                                ${assignToTeamButton}
                                <button class="view-idea-btn" title="View Details" data-idea-id="${idea.id}">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                                </button>
                                <span style="color: #3b82f6; font-size: 0.85rem; margin-left: 0.5rem;">Generating...</span>`;
                        } else {
                            actionButtons = `
                                ${assignToTeamButton}
                                <button class="view-idea-btn" title="View Details" data-idea-id="${idea.id}">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                                </button>`;
                        }
                    } else {
                        actionButtons = `
                            ${assignToTeamButton}
                            <button class="view-idea-btn" title="View Full Script" data-idea-id="${idea.id}">
                                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                            </button>`;
                    }

                    // Status display (only for text/voice ideas, not images)
                    const statusDisplay = contentType !== 'image' ? getStatusBadge(idea.status || 'draft') : '<span style="color: #64748b;">—</span>';
                    const statusDropdown = contentType !== 'image' ? `
                        <select class="status-dropdown" data-idea-id="${idea.id}" ${!idea.is_owner && idea.owner_username ? 'disabled' : ''}>
                            <option value="draft" ${(idea.status || 'draft') === 'draft' ? 'selected' : ''}>Draft</option>
                            <option value="in_progress" ${idea.status === 'in_progress' ? 'selected' : ''}>In Progress</option>
                            <option value="review" ${idea.status === 'review' ? 'selected' : ''}>Review</option>
                            <option value="completed" ${idea.status === 'completed' ? 'selected' : ''}>Completed</option>
                        </select>` : '<span style="color: #64748b;">—</span>';

                    return `
                    <tr data-id="${idea.id}" data-content-type="${contentType}" class="idea-row" style="cursor: pointer;">
                        <td>
                            <div class="idea-title-cell" style="display: flex; align-items: center; gap: 0.5rem;">
                                ${contentIcon}
                                <div>
                                    <strong>${escapeHtml(idea.title && idea.title.trim() ? idea.title : 'Untitled Idea')}</strong>
                                    ${ownerBadge}
                                </div>
                            </div>
                        </td>
                        <td>
                            ${contentBadge || '<span style="background: #64748b15; color: #64748b; padding: 0.2rem 0.5rem; border-radius: 6px; font-size: 0.75rem;">TEXT</span>'}
                        </td>
                        <td>
                            ${statusDisplay}
                        </td>
                        <td onclick="event.stopPropagation()">
                            ${statusDropdown}
                        </td>
                        <td>
                            ${idea.team_name ? `<span style="color: #ff7f50; font-size: 0.9rem; font-weight: 500;">${escapeHtml(idea.team_name)}</span>` : '<span style="color: #64748b; font-size: 0.9rem;">—</span>'}
                        </td>
                        <td>
                            ${idea.team_name ? `<span style="color: #ff7f50; font-size: 0.9rem;">${escapeHtml(idea.team_name)}</span>` : '<span style="color: #64748b; font-size: 0.9rem;">—</span>'}
                        </td>
                        <td>${new Date(idea.created_at).toLocaleDateString()}</td>
                        <td class="action-buttons" onclick="event.stopPropagation()">
                            ${actionButtons}
                            <button class="delete-idea-btn" title="Delete" data-idea-id="${idea.id}" data-content-type="${contentType}">
                                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
                            </button>
                        </td>
                    </tr>`;
                }).join('');

            // Attach click handlers for viewing ideas/images/videos
            tbody.querySelectorAll('.idea-row').forEach(row => {
                row.addEventListener('click', async () => {
                    const ideaId = parseInt(row.dataset.id);
                    const contentType = row.dataset.contentType || 'text';

                    if (contentType === 'image') {
                        // Find the image data from the ideas array
                        const imageData = ideas.find(i => i.id === ideaId && i.content_type === 'image');
                        if (imageData) {
                            await showImageModal(ideaId, imageData);
                        } else {
                            showFlash('Image data not found', 'error');
                        }
                    } else if (contentType === 'video') {
                        // Find the video data from the ideas array
                        const videoData = ideas.find(i => i.id === ideaId);
                        if (videoData && videoData.video_url && videoData.video_status === 'completed') {
                            await showVideoModal(ideaId, videoData, videoData.video_url);
                        } else if (videoData && videoData.video_status === 'processing') {
                            showFlash('Video is still generating. Please wait...', 'info');
                        } else if (videoData && videoData.video_status === 'failed') {
                            showFlash('Video generation failed', 'error');
                        } else {
                            showFlash('Video not available', 'error');
                        }
                    } else {
                        await showIdeaModal(ideaId);
                    }
                });
            });

            // Attach delete handlers
            tbody.querySelectorAll('.delete-idea-btn').forEach(btn => {
                btn.addEventListener('click', async () => {
                    const ideaId = btn.dataset.ideaId;
                    const contentType = btn.dataset.contentType || 'text';
                    await handleDeleteIdea(ideaId, contentType);
                });
            });

            // Attach assign team handlers
            tbody.querySelectorAll('.assign-team-btn').forEach(btn => {
                btn.addEventListener('click', async () => {
                    const ideaId = btn.dataset.ideaId;
                    await handleAssignToTeam(ideaId);
                });
            });

            // Attach view handlers for ideas (not images - images use view-image-btn)
            tbody.querySelectorAll('.view-idea-btn').forEach(btn => {
                btn.addEventListener('click', async () => {
                    const ideaId = parseInt(btn.dataset.ideaId);
                    await showIdeaModal(ideaId);
                });
            });

            // Attach status change handlers
            tbody.querySelectorAll('.status-dropdown').forEach(dropdown => {
                dropdown.addEventListener('change', async (e) => {
                    const ideaId = dropdown.dataset.ideaId;
                    const newStatus = dropdown.value;
                    await handleStatusChange(ideaId, newStatus);
                });
            });

            // Attach image view handlers
            tbody.querySelectorAll('.view-image-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    const imageId = parseInt(btn.dataset.ideaId);
                    const imageData = ideas.find(i => i.id === imageId && i.content_type === 'image');
                    if (imageData) {
                        showImageModal(imageId, imageData);
                    } else {
                        showFlash('Image data not found', 'error');
                    }
                });
            });

            // Attach image download handlers
            tbody.querySelectorAll('.download-image-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    const imageUrl = btn.dataset.imageUrl;
                    const imageId = btn.closest('.idea-row')?.dataset.id || 'image';
                    const filename = `generated-image-${imageId}.jpg`;
                    downloadImage(imageUrl, filename);
                });
            });

            // Attach voice play handlers
            tbody.querySelectorAll('.play-voice-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    const ideaId = btn.dataset.ideaId;
                    const voicePath = `/api/v1/ideas/voice/${ideaId}/download`;
                    const audio = new Audio(voicePath);
                    audio.play().catch(err => {
                        console.error('Audio playback failed:', err);
                        showFlash('Failed to play audio', 'error');
                    });
                });
            });

            // Attach voice download handlers
            tbody.querySelectorAll('.download-voice-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    const ideaId = btn.dataset.ideaId;
                    const link = document.createElement('a');
                    link.href = `/api/v1/ideas/voice/${ideaId}/download`;
                    link.download = `voice-${ideaId}.wav`;
                    link.click();
                });
            });

            // Attach video play handlers
            tbody.querySelectorAll('.play-video-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    const ideaId = btn.dataset.ideaId;
                    const videoUrl = btn.dataset.videoUrl;
                    const idea = ideas.find(i => i.id == ideaId);

                    if (videoUrl && idea) {
                        showVideoModal(ideaId, idea, videoUrl);
                    } else {
                        showFlash('Video URL not found', 'error');
                    }
                });
            });

            // Attach video download handlers
            tbody.querySelectorAll('.download-video-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    const videoUrl = btn.dataset.videoUrl;
                    const ideaId = btn.closest('.idea-row')?.dataset.id || 'video';

                    if (videoUrl) {
                        const link = document.createElement('a');
                        link.href = videoUrl;
                        link.download = `video-${ideaId}.mp4`;
                        link.target = '_blank';
                        link.click();
                    } else {
                        showFlash('Video URL not available', 'error');
                    }
                });
            });

        } catch (error) {
            showError('all-ideas-tbody', 'Failed to load ideas');
            console.error('Ideas render error:', error);
        }
    };

    const renderTeams = async () => {
        const teamsList = document.getElementById('teams-list');
        if (!teamsList) return;

        try {
            showLoading('teams-list');

            if (shouldRefreshCache('teams')) {
                const teamsData = await API.getTeams();
                updateCache('teams', teamsData.teams || []);
            }

            const teams = cache.teams;

            if (teams.length === 0) {
                teamsList.innerHTML = '<li>No teams yet. Create one below!</li>';
            } else {
                // Get current user ID to check ownership
                const currentUserId = cache.currentUser ? cache.currentUser.id : null;

                teamsList.innerHTML = teams.map(team => {
                    const isOwner = currentUserId && team.owner_id === currentUserId;

                    return `
                    <li data-id="${team.id}" class="team-list-item" style="display: flex; align-items: center; justify-content: space-between; padding-right: ${isOwner ? '0.5rem' : '1rem'};">
                        <span style="flex: 1; cursor: pointer;">${team.name}</span>
                        ${isOwner ? `
                            <button
                                class="delete-team-btn"
                                data-team-id="${team.id}"
                                data-team-name="${team.name.replace(/"/g, '&quot;')}"
                                title="Delete team (Owner only)"
                                style="background: none; border: none; color: #ef4444; cursor: pointer !important; padding: 0.25rem; display: flex; align-items: center; opacity: 0.6; transition: opacity 0.2s; pointer-events: auto;"
                                onmouseover="this.style.opacity='1'; this.style.cursor='pointer'"
                                onmouseout="this.style.opacity='0.6'">
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="pointer-events: none;">
                                    <polyline points="3 6 5 6 21 6"></polyline>
                                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                                </svg>
                            </button>
                        ` : ''}
                    </li>`;
                }).join('');
            }

            // Add click handlers for team items
            teamsList.querySelectorAll('.team-list-item').forEach(item => {
                const teamSpan = item.querySelector('span');
                if (teamSpan) {
                    teamSpan.addEventListener('click', async () => {
                        const teamId = parseInt(item.dataset.id);
                        await renderTeamDetails(teamId);
                        teamsList.querySelectorAll('.team-list-item').forEach(li => li.classList.remove('active'));
                        item.classList.add('active');
                    });
                }
            });

            // Add click handlers for delete buttons
            teamsList.querySelectorAll('.delete-team-btn').forEach(btn => {
                btn.addEventListener('click', async (e) => {
                    e.stopPropagation(); // Prevent team selection when clicking delete
                    const teamId = parseInt(btn.dataset.teamId);
                    const teamName = btn.dataset.teamName;
                    if (typeof window.deleteTeam === 'function') {
                        await window.deleteTeam(teamId, teamName);
                        // Refresh teams list after deletion
                        cache.lastFetch.teams = 0;
                        await renderTeams();
                    }
                });
            });

        } catch (error) {
            showError('teams-list', 'Failed to load teams');
            console.error('Teams render error:', error);
        }
    };

    const renderTeamDetails = async (teamId) => {
        // Get team data from cache
        const team = cache.teams.find(t => t.id === teamId);
        console.log('🔍 renderTeamDetails - Team ID:', teamId);
        console.log('🔍 renderTeamDetails - Team Data:', team);

        if (!team) {
            console.error('❌ Team not found in cache for ID:', teamId);
            return;
        }

        // Hide placeholder and show details
        const detailsPlaceholder = document.getElementById('team-details-placeholder');
        const detailsContent = document.getElementById('team-details-content');

        if (detailsPlaceholder) detailsPlaceholder.classList.add('hidden');
        if (detailsContent) detailsContent.classList.remove('hidden');

        // Update team name and description using existing HTML elements
        const teamNameEl = document.getElementById('selected-team-name');
        const teamDescEl = document.getElementById('selected-team-description');
        const inviteBtn = document.getElementById('invite-member-btn');
        const teamCallBtn = document.getElementById('start-team-call-btn');

        console.log('🔍 Invite button element found:', !!inviteBtn);
        console.log('🔍 Team call button element found:', !!teamCallBtn);

        if (teamNameEl) teamNameEl.textContent = team.name || 'Team';
        if (teamDescEl) teamDescEl.textContent = team.description || 'No description provided.';

        // Show/hide invite button based on user role (owner or admin only)
        const userRole = team.user_role || 'member';
        console.log('🔍 User Role:', userRole);
        console.log('🔍 Should show invite button?', userRole === 'owner' || userRole === 'admin');

        if (inviteBtn) {
            const shouldShow = (userRole === 'owner' || userRole === 'admin');
            inviteBtn.style.display = shouldShow ? 'flex' : 'none';
            console.log('🔍 Invite button display set to:', inviteBtn.style.display);
        }

        // Show team call button for all members
        if (teamCallBtn) {
            teamCallBtn.style.display = 'flex';
            console.log('🔍 Team call button display set to:', teamCallBtn.style.display);
        }

        // Set global currentTeamId and currentUserRole for teams.js
        window.currentTeamId = teamId;
        window.currentUserRole = userRole;

        // Load team members using teams.js function if available
        if (typeof window.loadTeamMembers === 'function') {
            await window.loadTeamMembers(teamId);
        }

        // Load team ideas
        await renderTeamIdeasSection(teamId);

        // Load team flowcharts
        await renderTeamFlowchartsSection(teamId);
    };

    const renderTeamIdeasSection = async (teamId) => {
        const teamIdeasList = document.getElementById('team-ideas-list');
        if (!teamIdeasList) {
            console.error('team-ideas-list element not found');
            return;
        }

        try {
            // Show loading state
            teamIdeasList.innerHTML = '<div style="text-align: center; padding: 2rem; color: #64748b;">Loading team ideas...</div>';

            // Fetch team ideas
            const teamIdeasData = await API.getTeamIdeas();
            const allTeamIdeas = teamIdeasData.ideas || [];

            // Filter for ideas assigned to this specific team
            const teamSpecificIdeas = allTeamIdeas.filter(idea => idea.team_id === teamId);

            console.log(`📋 Found ${teamSpecificIdeas.length} ideas for team ${teamId}`);

            if (teamSpecificIdeas.length === 0) {
                teamIdeasList.innerHTML = `
                    <div style="text-align: center; padding: 2rem; color: #64748b;">
                        <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="opacity: 0.3; margin-bottom: 1rem;">
                            <path d="M12 20h9"></path>
                            <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path>
                        </svg>
                        <p>No ideas assigned to this team yet.</p>
                        <p style="font-size: 0.875rem; margin-top: 0.5rem; opacity: 0.7;">Team members can assign their ideas to share with the team.</p>
                    </div>`;
                return;
            }

            // Render team ideas as cards
            teamIdeasList.innerHTML = teamSpecificIdeas.map(idea => {
                const statusColors = {
                    'draft': '#94a3b8',
                    'in_progress': '#3b82f6',
                    'review': '#f59e0b',
                    'completed': '#10b981'
                };
                const statusColor = statusColors[idea.status] || '#94a3b8';

                return `
                    <div class="idea-card" data-idea-id="${idea.id}" style="
                        border: 1px solid rgba(255, 255, 255, 0.15);
                        border-radius: 8px;
                        padding: 1rem;
                        margin-bottom: 1rem;
                        cursor: pointer;
                        transition: all 0.2s;
                        background: rgba(255, 255, 255, 0.05);
                    "
                    onmouseover="this.style.borderColor='#3b82f6'; this.style.boxShadow='0 2px 8px rgba(59, 130, 246, 0.3)'"
                    onmouseout="this.style.borderColor='rgba(255, 255, 255, 0.15)'; this.style.boxShadow='none'">
                        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 0.5rem;">
                            <h4 style="margin: 0; color: #e2e8f0; font-size: 1rem; font-weight: 600;">
                                ${escapeHtml(idea.title || 'Untitled Idea')}
                            </h4>
                            <span style="
                                padding: 0.25rem 0.75rem;
                                border-radius: 12px;
                                background-color: ${statusColor}25;
                                color: ${statusColor};
                                font-size: 0.75rem;
                                font-weight: 500;
                                white-space: nowrap;
                            ">${idea.status.replace('_', ' ')}</span>
                        </div>
                        ${idea.description ? `<p style="margin: 0.5rem 0 0 0; color: #94a3b8; font-size: 0.875rem; line-height: 1.5;">${escapeHtml(idea.description.substring(0, 150))}${idea.description.length > 150 ? '...' : ''}</p>` : ''}
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid rgba(255, 255, 255, 0.1);">
                            <span style="color: #94a3b8; font-size: 0.8rem;">
                                by <strong style="color: #ff7f50;">@${escapeHtml(idea.owner_username)}</strong>
                            </span>
                            <span style="color: #94a3b8; font-size: 0.8rem;">
                                ${new Date(idea.created_at).toLocaleDateString()}
                            </span>
                        </div>
                    </div>
                `;
            }).join('');

            // Add click handlers to idea cards
            teamIdeasList.querySelectorAll('.idea-card').forEach(card => {
                card.addEventListener('click', async () => {
                    const ideaId = parseInt(card.dataset.ideaId);
                    await showIdeaModal(ideaId);
                });
            });

        } catch (error) {
            console.error('Error loading team ideas:', error);
            teamIdeasList.innerHTML = `
                <div style="text-align: center; padding: 2rem; color: #ef4444;">
                    <p>Failed to load team ideas.</p>
                    <p style="font-size: 0.875rem; margin-top: 0.5rem;">${escapeHtml(error.message)}</p>
                </div>`;
        }
    };

    const renderTeamFlowchartsSection = async (teamId) => {
        const teamFlowchartsList = document.getElementById('team-flowcharts-list');
        if (!teamFlowchartsList) {
            console.error('team-flowcharts-list element not found');
            return;
        }

        try {
            // Show loading state
            teamFlowchartsList.innerHTML = '<div style="text-align: center; padding: 2rem; color: #64748b;">Loading team flowcharts...</div>';

            // Fetch team flowcharts with team_id parameter
            const response = await fetch(`/api/v1/flowcharts?team_id=${teamId}`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('sessionToken') || ''}`
                },
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error(`Failed to fetch team flowcharts: ${response.statusText}`);
            }

            const teamFlowcharts = await response.json();

            console.log(`📊 Found ${teamFlowcharts.length} flowcharts for team ${teamId}`);

            if (teamFlowcharts.length === 0) {
                teamFlowchartsList.innerHTML = `
                    <div style="text-align: center; padding: 2rem; color: #64748b;">
                        <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="opacity: 0.3; margin-bottom: 1rem;">
                            <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
                            <line x1="9" y1="9" x2="15" y2="9"></line>
                            <line x1="9" y1="15" x2="15" y2="15"></line>
                        </svg>
                        <p>No flowcharts shared with this team yet.</p>
                        <p style="font-size: 0.875rem; margin-top: 0.5rem; opacity: 0.7;">Create a flowchart in the Planner tab and assign it to this team.</p>
                    </div>`;
                return;
            }

            // Render team flowcharts as cards
            teamFlowchartsList.innerHTML = teamFlowcharts.map(flowchart => {
                const statusColors = {
                    'draft': '#94a3b8',
                    'in_progress': '#3b82f6',
                    'review': '#f59e0b',
                    'completed': '#10b981',
                    'archived': '#6b7280'
                };
                const statusColor = statusColors[flowchart.status] || '#94a3b8';

                return `
                    <div class="flowchart-card" data-flowchart-id="${flowchart.id}" style="
                        border: 1px solid rgba(255, 255, 255, 0.15);
                        border-radius: 8px;
                        padding: 1rem;
                        margin-bottom: 1rem;
                        cursor: pointer;
                        transition: all 0.2s;
                        background: rgba(255, 255, 255, 0.05);
                    "
                    onmouseover="this.style.borderColor='#8b5cf6'; this.style.boxShadow='0 2px 8px rgba(139, 92, 246, 0.3)'"
                    onmouseout="this.style.borderColor='rgba(255, 255, 255, 0.15)'; this.style.boxShadow='none'">
                        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 0.5rem;">
                            <div style="display: flex; align-items: center; gap: 0.5rem;">
                                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#8b5cf6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
                                    <line x1="9" y1="9" x2="15" y2="9"></line>
                                    <line x1="9" y1="15" x2="15" y2="15"></line>
                                </svg>
                                <h4 style="margin: 0; color: #e2e8f0; font-size: 1rem; font-weight: 600;">
                                    ${escapeHtml(flowchart.title || 'Untitled Flowchart')}
                                </h4>
                            </div>
                            <span style="
                                padding: 0.25rem 0.75rem;
                                border-radius: 12px;
                                background-color: ${statusColor}25;
                                color: ${statusColor};
                                font-size: 0.75rem;
                                font-weight: 500;
                                white-space: nowrap;
                            ">${flowchart.status.replace('_', ' ')}</span>
                        </div>
                        ${flowchart.description ? `<p style="margin: 0.5rem 0 0 0; color: #94a3b8; font-size: 0.875rem; line-height: 1.5;">${escapeHtml(flowchart.description.substring(0, 150))}${flowchart.description.length > 150 ? '...' : ''}</p>` : ''}
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid rgba(255, 255, 255, 0.1);">
                            <span style="color: #94a3b8; font-size: 0.8rem;">
                                <strong style="color: #8b5cf6;">Team Flowchart</strong>
                            </span>
                            <span style="color: #94a3b8; font-size: 0.8rem;">
                                ${new Date(flowchart.updated_at).toLocaleDateString()}
                            </span>
                        </div>
                    </div>
                `;
            }).join('');

            // Add click handlers to flowchart cards to open in Planner tab
            teamFlowchartsList.querySelectorAll('.flowchart-card').forEach(card => {
                card.addEventListener('click', async () => {
                    const flowchartId = parseInt(card.dataset.flowchartId);
                    console.log(`🎯 Flowchart card clicked! ID: ${flowchartId}`);

                    // Switch to Planner tab (flowchart-page)
                    const plannerLink = document.querySelector('a.nav-item[data-page="flowchart-page"]');
                    if (plannerLink) {
                        console.log('🔄 Switching to Planner tab...');
                        plannerLink.click();

                        // Wait for tab to load, then open the flowchart
                        setTimeout(async () => {
                            console.log('⏰ Timeout fired, checking for openFlowchart function...');
                            console.log(`📝 window.openFlowchart type: ${typeof window.openFlowchart}`);

                            try {
                                // Check if openFlowchart function exists (from flowchart-dashboard.js)
                                if (typeof window.openFlowchart === 'function') {
                                    console.log(`✅ Calling openFlowchart(${flowchartId})`);
                                    await window.openFlowchart(flowchartId);
                                    console.log('✅ openFlowchart completed');
                                } else {
                                    console.warn('⚠️ openFlowchart function not found on window object');
                                    console.log('Available window properties:', Object.keys(window).filter(k => k.includes('flowchart')));
                                    showNotification('Please try opening the flowchart from the Planner tab', 'warning');
                                }
                            } catch (error) {
                                console.error('❌ Error opening flowchart:', error);
                                showNotification('Failed to load flowchart', 'error');
                            }
                        }, 500);
                    } else {
                        console.error('❌ Planner tab link not found!');
                    }
                });
            });

        } catch (error) {
            console.error('Error loading team flowcharts:', error);
            teamFlowchartsList.innerHTML = `
                <div style="text-align: center; padding: 2rem; color: #ef4444;">
                    <p>Failed to load team flowcharts.</p>
                    <p style="font-size: 0.875rem; margin-top: 0.5rem;">${escapeHtml(error.message)}</p>
                </div>`;
        }
    };

    const populateTeamDrivesSidebar = async () => {
        const teamDrivesList = document.getElementById('team-drives-list');
        if (!teamDrivesList) return;

        try {
            // Fetch teams if not already cached
            if (shouldRefreshCache('teams')) {
                const teamsData = await API.getTeams();
                updateCache('teams', teamsData.teams || []);
            }

            const teams = cache.teams;

            if (teams.length === 0) {
                teamDrivesList.innerHTML = '<li style="padding: 0.5rem; color: var(--text-secondary); font-size: 0.85rem;">No team drives</li>';
                return;
            }

            teamDrivesList.innerHTML = teams.map(team => {
                // Get current user ID to check ownership
                const currentUserId = cache.currentUser ? cache.currentUser.id : null;
                const isOwner = currentUserId && team.owner_id === currentUserId;

                return `
                <li data-team-id="${team.id}" class="team-drive-item" style="cursor: pointer; display: flex; align-items: center; justify-content: space-between; padding-right: ${isOwner ? '0.25rem' : '0.5rem'};">
                    <div style="display: flex; align-items: center; flex: 1;">
                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 0.5rem;"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>
                        <span>${team.name}</span>
                    </div>
                    ${isOwner ? `
                        <button
                            class="delete-team-btn"
                            data-team-id="${team.id}"
                            data-team-name="${team.name.replace(/"/g, '&quot;')}"
                            title="Delete team (Owner only)"
                            style="background: none; border: none; color: #ef4444; cursor: pointer !important; padding: 0.25rem; display: flex; align-items: center; opacity: 0.6; transition: opacity 0.2s; pointer-events: auto;"
                            onmouseover="this.style.opacity='1'; this.style.cursor='pointer'"
                            onmouseout="this.style.opacity='0.6'">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="pointer-events: none;">
                                <polyline points="3 6 5 6 21 6"></polyline>
                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                            </svg>
                        </button>
                    ` : ''}
                </li>`;
            }).join('');

            // Add click handlers for team drives
            teamDrivesList.querySelectorAll('.team-drive-item').forEach(item => {
                item.addEventListener('click', async () => {
                    const teamId = parseInt(item.dataset.teamId);

                    // Highlight selected team drive
                    teamDrivesList.querySelectorAll('.team-drive-item').forEach(li => li.classList.remove('active'));
                    item.classList.add('active');

                    // Unhighlight "My Drive"
                    const myDriveList = document.getElementById('my-drive-list');
                    if (myDriveList) {
                        myDriveList.querySelectorAll('li').forEach(li => li.classList.remove('active'));
                    }

                    // Render team drive
                    await renderDrive(teamId);
                });
            });

            // Add event handlers for delete buttons
            teamDrivesList.querySelectorAll('.delete-team-btn').forEach(btn => {
                btn.addEventListener('click', async (e) => {
                    e.stopPropagation(); // Prevent team selection when clicking delete
                    const teamId = parseInt(btn.dataset.teamId);
                    const teamName = btn.dataset.teamName;
                    if (typeof window.deleteTeam === 'function') {
                        await window.deleteTeam(teamId, teamName);
                    }
                });
            });

            // Add "My Drive" click handler
            const myDriveList = document.getElementById('my-drive-list');
            if (myDriveList && myDriveList.children.length === 0) {
                myDriveList.innerHTML = '<li class="my-drive-item active" style="cursor: pointer;">📁 Personal Drive</li>';

                myDriveList.querySelector('.my-drive-item').addEventListener('click', async () => {
                    // Highlight My Drive
                    myDriveList.querySelector('.my-drive-item').classList.add('active');

                    // Unhighlight team drives
                    teamDrivesList.querySelectorAll('.team-drive-item').forEach(li => li.classList.remove('active'));

                    // Render personal drive
                    await renderDrive(null);
                });
            }

        } catch (error) {
            console.error('Failed to populate team drives:', error);
        }
    };

    // Function to update storage usage indicator
    const updateStorageUsage = async () => {
        try {
            const data = await API.request('/api/v1/drive/storage/usage');

            const usageText = document.getElementById('storage-usage-text');
            const usageFill = document.getElementById('storage-usage-fill');

            if (usageText && usageFill) {
                // Update text
                usageText.textContent = `${data.usage_mb} MB / ${data.limit_mb} MB`;

                // Update progress bar
                usageFill.style.width = `${data.usage_percentage}%`;

                // Change color if usage is high (>80%)
                if (data.usage_percentage > 80) {
                    usageFill.setAttribute('data-usage', 'high');
                } else {
                    usageFill.removeAttribute('data-usage');
                }
            }
        } catch (error) {
            console.error('Failed to fetch storage usage:', error);
        }
    };

    const renderDrive = async (teamId = null) => {
        const filesGrid = document.getElementById('files-grid');
        if (!filesGrid) return;

        try {
            showLoading('files-grid');

            // Update current team ID
            currentTeamId = teamId;

            // Update storage usage for personal drive
            if (!teamId) {
                updateStorageUsage();
            }

            // Fetch folders, files, and notes in parallel (with team filter if needed)
            const foldersPromise = teamId
                ? API.request(`/api/v1/drive/folders?team_id=${teamId}`)
                : API.request('/api/v1/drive/folders');

            const filesPromise = teamId
                ? API.request(`/api/v1/drive/files?team_id=${teamId}`)
                : API.getFiles();

            const notesPromise = shouldRefreshCache('notes') ? API.getNotes() : Promise.resolve({notes: cache.notes});

            const [foldersData, filesData, notesData] = await Promise.all([foldersPromise, filesPromise, notesPromise]);

            const folders = foldersData.folders || [];
            const files = filesData.files || [];
            const notes = notesData.notes || [];

            if (!shouldRefreshCache('notes')) {
                updateCache('notes', notes);
            }

            // Populate team drives sidebar if not already done
            await populateTeamDrivesSidebar();

            const items = [];

            // Add folders
            folders.forEach(folder => {
                const teamBadge = folder.team_id ? '<span class="team-badge" title="Team folder">👥</span>' : '';
                items.push(`
                    <div class="file-item card ${folder.team_id ? 'team-item' : ''}" data-type="folder" data-id="${folder.id}" data-name="${folder.name}">
                        <div class="file-item-icon">📁</div>
                        <div class="file-item-name">${encryptionIconHTML} ${folder.name} ${teamBadge}</div>
                        <div class="file-item-actions">
                            <button class="item-action-btn share-item-btn" title="Share to Team" ${folder.team_id ? 'disabled' : ''}>
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"></circle><circle cx="6" cy="12" r="3"></circle><circle cx="18" cy="19" r="3"></circle><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line></svg>
                            </button>
                            <button class="item-action-btn download-folder-btn" title="Download as ZIP" data-folder-id="${folder.id}">
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                            </button>
                            <button class="item-action-btn delete-item-btn" title="Delete">
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
                            </button>
                        </div>
                    </div>`);
            });

            // Add files
            files.forEach(file => {
                const sizeKB = (file.size / 1024).toFixed(1);
                const teamBadge = file.team_id ? '<span class="team-badge" title="Team file">👥</span>' : '';
                items.push(`
                    <div class="file-item card ${file.team_id ? 'team-item' : ''}" data-type="file" data-id="${file.id}" data-name="${file.filename}">
                        <div class="file-item-icon">📄</div>
                        <div class="file-item-name">${encryptionIconHTML} ${file.filename} ${teamBadge}</div>
                        <div class="file-item-meta">${sizeKB} KB</div>
                        <div class="file-item-actions">
                            <button class="item-action-btn share-item-btn" title="Share to Team" ${file.team_id ? 'disabled' : ''}>
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"></circle><circle cx="6" cy="12" r="3"></circle><circle cx="18" cy="19" r="3"></circle><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line></svg>
                            </button>
                            <button class="item-action-btn download-item-btn" title="Download">
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                            </button>
                            <button class="item-action-btn delete-item-btn" title="Delete">
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
                            </button>
                        </div>
                    </div>`);
            });

            // Add notes (now decrypted by backend)
            notes.forEach(note => {
                const noteTitle = note.title || 'Untitled Note';
                const teamBadge = note.team_id ? '<span class="team-badge" title="Team note">👥</span>' : '';
                items.push(`
                    <div class="file-item card ${note.team_id ? 'team-item' : ''}" data-type="note" data-id="${note.id}" data-name="${noteTitle}">
                        <div class="file-item-icon">📝</div>
                        <div class="file-item-name">${encryptionIconHTML} ${noteTitle} ${teamBadge}</div>
                        <div class="file-item-actions">
                            <button class="item-action-btn share-item-btn" title="Share to Team" ${note.team_id ? 'disabled' : ''}>
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"></circle><circle cx="6" cy="12" r="3"></circle><circle cx="18" cy="19" r="3"></circle><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line></svg>
                            </button>
                            <button class="item-action-btn download-item-btn" title="Download">
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                            </button>
                            <button class="item-action-btn delete-item-btn" title="Delete">
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                            </button>
                        </div>
                    </div>`);
            });

            filesGrid.innerHTML = items.length === 0
                ? '<p>No files, folders, or notes yet. Upload or create something!</p>'
                : items.join('');

            // Add event handlers for download and delete buttons
            filesGrid.querySelectorAll('.download-item-btn').forEach(btn => {
                btn.addEventListener('click', async (e) => {
                    e.stopPropagation();
                    const fileItem = btn.closest('.file-item');
                    const fileId = fileItem.dataset.id;
                    const fileType = fileItem.dataset.type;

                    if (fileType === 'file') {
                        try {
                            const response = await API.downloadFile(fileId);
                            const blob = await response.blob();
                            const url = window.URL.createObjectURL(blob);
                            const a = document.createElement('a');
                            a.href = url;
                            a.download = fileItem.querySelector('.file-item-name').textContent.trim().replace('🔒 ', '');
                            document.body.appendChild(a);
                            a.click();
                            window.URL.revokeObjectURL(url);
                            document.body.removeChild(a);
                            showFlash('File downloaded successfully', 'success');
                        } catch (error) {
                            showFlash('Failed to download file: ' + error.message, 'error');
                        }
                    } else if (fileType === 'note') {
                        try {
                            // Get note content
                            const noteData = await API.getNote(fileId);
                            const noteTitle = noteData.title || 'Untitled Note';
                            const noteContent = noteData.content || '';

                            // Create text file with note content
                            const textContent = `${noteTitle}\n${'='.repeat(noteTitle.length)}\n\n${noteContent}`;
                            const blob = new Blob([textContent], { type: 'text/plain' });
                            const url = window.URL.createObjectURL(blob);
                            const a = document.createElement('a');
                            a.href = url;
                            a.download = `${noteTitle}.txt`;
                            document.body.appendChild(a);
                            a.click();
                            window.URL.revokeObjectURL(url);
                            document.body.removeChild(a);
                            showFlash('Note downloaded successfully', 'success');
                        } catch (error) {
                            showFlash('Failed to download note: ' + error.message, 'error');
                        }
                    }
                });
            });

            filesGrid.querySelectorAll('.delete-item-btn').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const fileItem = btn.closest('.file-item');
                    const itemId = fileItem.dataset.id;
                    const itemType = fileItem.dataset.type;
                    const fileName = fileItem.querySelector('.file-name')?.textContent || 'this item';

                    openDeleteFileModal(itemId, itemType, fileName);
                });
            });

            // Add share button handlers
            filesGrid.querySelectorAll('.share-item-btn').forEach(btn => {
                btn.addEventListener('click', async (e) => {
                    e.stopPropagation();
                    const fileItem = btn.closest('.file-item');
                    const itemId = fileItem.dataset.id;
                    const itemType = fileItem.dataset.type;
                    const itemName = fileItem.dataset.name;

                    // Store current item data for sharing
                    window.currentShareItem = {
                        id: itemId,
                        type: itemType,
                        name: itemName
                    };

                    // Fetch and populate teams
                    await populateTeamsDropdown();

                    // Show share modal
                    const overlay = document.getElementById('share-modal-overlay');
                    const modal = document.getElementById('share-modal');
                    overlay.classList.add('active');
                    modal.classList.add('active');
                });
            });

            // Add folder download handlers
            filesGrid.querySelectorAll('.download-folder-btn').forEach(btn => {
                btn.addEventListener('click', async (e) => {
                    e.stopPropagation();
                    const folderId = btn.dataset.folderId;

                    try {
                        showFlash('Preparing folder download...', 'info', 2000);

                        // Session token is sent automatically by browser in httpOnly cookie
                        const response = await fetch(`/api/v1/drive/folders/${folderId}/download`, {
                            credentials: 'same-origin'  // Include cookies
                        });

                        if (!response.ok) {
                            const errorData = await response.json().catch(() => ({}));
                            throw new Error(errorData.detail || 'Failed to download folder');
                        }

                        // Get filename from Content-Disposition header
                        const contentDisposition = response.headers.get('Content-Disposition');
                        let filename = 'folder.zip';
                        if (contentDisposition) {
                            const matches = /filename="(.+)"/.exec(contentDisposition);
                            if (matches && matches[1]) {
                                filename = matches[1];
                            }
                        }

                        // Download the ZIP file
                        const blob = await response.blob();
                        const url = window.URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = filename;
                        document.body.appendChild(a);
                        a.click();
                        window.URL.revokeObjectURL(url);
                        document.body.removeChild(a);

                        showFlash('Folder downloaded successfully', 'success');
                    } catch (error) {
                        showFlash('Failed to download folder: ' + error.message, 'error');
                    }
                });
            });

            // Add click handlers for file items (to view/preview)
            filesGrid.querySelectorAll('.file-item').forEach(item => {
                item.addEventListener('click', async (e) => {
                    // Don't trigger if clicking on action buttons
                    if (e.target.closest('.item-action-btn')) {
                        return;
                    }

                    const itemId = item.dataset.id;
                    const itemType = item.dataset.type;

                    if (itemType === 'folder') {
                        // Open folder contents modal
                        try {
                            const response = await API.request(`/api/v1/drive/folders/${itemId}/contents`);
                            const folderName = response.folder_name || 'Folder';
                            const contents = response.contents || [];

                            // Set current folder ID for uploads
                            currentFolderId = parseInt(itemId);

                            document.getElementById('folder-contents-title').textContent = `📁 ${folderName}`;

                            const contentsGrid = document.getElementById('folder-contents-grid');

                            if (contents.length === 0) {
                                contentsGrid.innerHTML = '<p>This folder is empty</p>';
                            } else {
                                const items = contents.map(item => {
                                    const icon = item.type === 'folder' ? '📁' :
                                                item.type === 'note' ? '📝' : '📄';
                                    const sizeInfo = item.size ? `<div class="file-item-meta">${(item.size / 1024).toFixed(1)} KB</div>` : '';
                                    const createdDate = item.created_at ? new Date(item.created_at).toLocaleDateString() : '';

                                    return `
                                        <div class="file-item card">
                                            <div class="file-item-icon">${icon}</div>
                                            <div class="file-item-name">${item.name}</div>
                                            ${sizeInfo}
                                            <div class="file-item-meta">${createdDate}</div>
                                        </div>
                                    `;
                                }).join('');

                                contentsGrid.innerHTML = items;
                            }

                            const overlay = document.getElementById('folder-contents-modal-overlay');
                            const modal = document.getElementById('folder-contents-modal');
                            overlay.classList.add('active');
                            modal.classList.add('active');
                            overlay.style.display = 'grid';
                            overlay.style.opacity = '1';
                            overlay.style.zIndex = '9999';
                            modal.style.display = 'flex';
                            modal.style.opacity = '1';
                            modal.style.transform = 'scale(1)';
                        } catch (error) {
                            showFlash('Failed to load folder contents: ' + error.message, 'error');
                        }
                    } else if (itemType === 'note') {
                        // Show note content in modal
                        try {
                            const noteData = await API.getNote(itemId);
                            const noteTitle = noteData.title || 'Untitled Note';
                            const noteContent = noteData.content || '';

                            document.getElementById('view-content-title').textContent = noteTitle;
                            document.getElementById('view-content-body').textContent = noteContent;

                            const overlay = document.getElementById('modal-overlay');
                            const modal = document.getElementById('view-content-modal');
                            overlay.classList.add('active');
                            modal.classList.add('active');
                            overlay.style.display = 'grid';
                            overlay.style.opacity = '1';
                            overlay.style.zIndex = '9999';
                            modal.style.display = 'flex';
                            modal.style.opacity = '1';
                            modal.style.transform = 'scale(1)';
                        } catch (error) {
                            showFlash('Failed to load note: ' + error.message, 'error');
                        }
                    } else if (itemType === 'file') {
                        // Open file preview modal
                        const filename = item.querySelector('.file-item-name').textContent.trim().replace('🔒 ', '');
                        document.getElementById('file-preview-title').textContent = filename;

                        // Show preview modal
                        const overlay = document.getElementById('file-preview-modal-overlay');
                        const modal = document.getElementById('file-preview-modal');
                        overlay.classList.add('active');
                        modal.classList.add('active');
                        overlay.style.display = 'grid';
                        overlay.style.opacity = '1';
                        overlay.style.zIndex = '9999';
                        modal.style.display = 'flex';
                        modal.style.opacity = '1';
                        modal.style.transform = 'scale(1)';

                        // Try to load preview
                        try {
                            const response = await API.downloadFile(itemId);
                            const blob = await response.blob();
                            const fileType = blob.type;
                            const fileExt = filename.split('.').pop().toLowerCase();

                            // Hide all preview elements
                            document.getElementById('file-preview-image').style.display = 'none';
                            document.getElementById('file-preview-text').style.display = 'none';
                            document.getElementById('file-preview-pdf').style.display = 'none';
                            document.getElementById('file-preview-csv').style.display = 'none';
                            document.getElementById('file-preview-unsupported').style.display = 'none';

                            if (fileType.startsWith('image/') || ['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(fileExt)) {
                                // Show image preview
                                const url = URL.createObjectURL(blob);
                                const img = document.getElementById('file-preview-image');
                                img.src = url;
                                img.style.display = 'block';
                                img.onload = () => URL.revokeObjectURL(url);
                            } else if (fileType === 'application/pdf' || fileExt === 'pdf') {
                                // Show PDF preview in iframe
                                const url = URL.createObjectURL(blob);
                                const iframe = document.getElementById('file-preview-pdf');
                                iframe.src = url;
                                iframe.style.display = 'block';
                            } else if (fileExt === 'csv' || fileType === 'text/csv') {
                                // Parse and show CSV as table
                                const text = await blob.text();
                                const lines = text.split('\n').filter(line => line.trim());

                                if (lines.length > 0) {
                                    const table = document.getElementById('csv-preview-table');
                                    const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, ''));

                                    let tableHTML = '<thead><tr>';
                                    headers.forEach(header => {
                                        tableHTML += `<th>${header}</th>`;
                                    });
                                    tableHTML += '</tr></thead><tbody>';

                                    for (let i = 1; i < lines.length; i++) {
                                        const cells = lines[i].split(',').map(c => c.trim().replace(/^"|"$/g, ''));
                                        tableHTML += '<tr>';
                                        cells.forEach(cell => {
                                            tableHTML += `<td>${cell}</td>`;
                                        });
                                        tableHTML += '</tr>';
                                    }

                                    tableHTML += '</tbody>';
                                    table.innerHTML = tableHTML;
                                    document.getElementById('file-preview-csv').style.display = 'block';
                                }
                            } else if (fileType.startsWith('text/') || fileExt === 'txt') {
                                // Show text preview
                                const text = await blob.text();
                                document.getElementById('file-preview-text').textContent = text;
                                document.getElementById('file-preview-text').style.display = 'block';
                            } else {
                                // Unsupported type (e.g., DOCX)
                                document.getElementById('file-preview-unsupported').style.display = 'block';
                                document.getElementById('download-from-preview').onclick = () => {
                                    const url = URL.createObjectURL(blob);
                                    const a = document.createElement('a');
                                    a.href = url;
                                    a.download = filename;
                                    a.click();
                                    URL.revokeObjectURL(url);
                                };
                            }
                        } catch (error) {
                            showFlash('Failed to load preview: ' + error.message, 'error');
                        }
                    }
                });
            });

        } catch (error) {
            showError('files-grid', 'Failed to load drive files');
            console.error('Drive render error:', error);
        }
    };

    // Export renderDrive globally so delete modal can refresh UI
    window.renderDrive = renderDrive;

    const renderConversationList = async () => {
        const directConversations = document.getElementById('direct-conversations');
        const teamConversations = document.getElementById('team-conversations');

        if (!directConversations || !teamConversations) return;

        try {
            showLoading('direct-conversations');
            showLoading('team-conversations');

            // Fetch messages
            if (shouldRefreshCache('messages')) {
                const inboxData = await API.getInboxMessages();
                const sentData = await API.getSentMessages();
                const allMessages = [...(inboxData.messages || []), ...(sentData.messages || [])];
                updateCache('messages', allMessages);
            }

            const messages = cache.messages;

            // Group messages by sender/receiver
            const conversations = {};
            messages.forEach(msg => {
                const otherUserId = msg.sender_id === cache.currentUser.id ? msg.receiver_id : msg.sender_id;
                if (!conversations[otherUserId]) {
                    conversations[otherUserId] = [];
                }
                conversations[otherUserId].push(msg);
            });

            directConversations.innerHTML = Object.keys(conversations).length === 0
                ? '<p style="padding: 1rem;">No messages yet.</p>'
                : Object.keys(conversations).map(userId => {
                    const messages = conversations[userId];
                    const lastMessage = messages[messages.length - 1];
                    return `
                        <div class="conversation-item" data-type="user" data-id="${userId}">
                            ${createAvatar('U')}
                            <div class="conversation-info">
                                <div class="name">User ${userId}</div>
                                <div class="last-message">${lastMessage.content_receiver || lastMessage.content_sender || 'Encrypted message'}</div>
                            </div>
                        </div>`;
                }).join('');

            teamConversations.innerHTML = '<p style="padding: 1rem;">No team conversations.</p>';

        } catch (error) {
            showError('direct-conversations', 'Failed to load conversations');
            console.error('Conversations render error:', error);
        }
    };

    // ===== FORM HANDLERS =====

    // Create Idea Form
    const createIdeaForm = document.getElementById('text-form');
    if (createIdeaForm) {
        createIdeaForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const formData = {
                title: document.getElementById('text-title').value,
                description: document.getElementById('text-description').value,
                content: document.getElementById('text-content').value,
                team_id: parseInt(document.getElementById('text-team').value) || null,
                status: document.getElementById('text-status').value
            };

            try {
                const result = await API.createIdea(formData);
                showFlash('Idea created successfully!', 'success');
                createIdeaForm.reset();

                // Refresh cache
                cache.lastFetch.ideas = 0;
                await renderDashboard();
                await renderAllIdeas();
            } catch (error) {
                showFlash('Failed to create idea: ' + error.message, 'error');
            }
        });
    }

    // Create Team Form
    const createTeamForm = document.getElementById('create-team-form');
    if (createTeamForm) {
        createTeamForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const formData = {
                name: document.getElementById('team-name').value,
                description: document.getElementById('team-description')?.value || ''
            };

            try {
                const result = await API.createTeam(formData);
                showFlash('Team created successfully!', 'success');
                createTeamForm.reset();

                // Refresh cache
                cache.lastFetch.teams = 0;
                await renderTeams();
            } catch (error) {
                showFlash('Failed to create team: ' + error.message, 'error');
            }
        });
    }

    // Send Message Form
    const sendMessageForm = document.getElementById('compose-message-form');
    if (sendMessageForm) {
        sendMessageForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const formData = {
                receiver_id: parseInt(document.getElementById('message-receiver').value),
                subject: document.getElementById('message-subject').value,
                content: document.getElementById('message-content').value
            };

            try {
                const result = await API.sendMessage(formData);
                showFlash('Message sent successfully!', 'success');
                sendMessageForm.reset();

                // Close modal
                document.getElementById('compose-message-modal-overlay').classList.remove('active');
                document.getElementById('compose-message-modal').classList.remove('active');

                // Refresh messages
                cache.lastFetch.messages = 0;
                await renderConversationList();
            } catch (error) {
                showFlash('Failed to send message: ' + error.message, 'error');
            }
        });
    }

    // Change Password Form
    const changePasswordForm = document.getElementById('change-password-form');
    if (changePasswordForm) {
        const newPasswordInput = document.getElementById('new-password');
        const confirmPasswordInput = document.getElementById('confirm-password');
        const strengthIndicator = document.getElementById('password-strength');
        const strengthBar = document.getElementById('strength-bar-fill');
        const strengthText = document.getElementById('strength-text');

        // Password strength checker
        const checkPasswordStrength = (password) => {
            let strength = 0;
            const checks = {
                length: password.length >= 14,
                lowercase: /[a-z]/.test(password),
                uppercase: /[A-Z]/.test(password),
                number: /\d/.test(password),
                special: /[@$!%*?&]/.test(password)
            };

            strength += checks.length ? 20 : 0;
            strength += checks.lowercase ? 20 : 0;
            strength += checks.uppercase ? 20 : 0;
            strength += checks.number ? 20 : 0;
            strength += checks.special ? 20 : 0;

            return { strength, checks };
        };

        // Show password strength on input
        if (newPasswordInput && strengthIndicator) {
            newPasswordInput.addEventListener('input', (e) => {
                const password = e.target.value;
                if (password.length === 0) {
                    strengthIndicator.style.display = 'none';
                    return;
                }

                strengthIndicator.style.display = 'block';
                const { strength, checks } = checkPasswordStrength(password);

                strengthBar.style.width = strength + '%';

                if (strength < 60) {
                    strengthBar.style.backgroundColor = '#ef4444';
                    strengthText.textContent = 'Weak';
                    strengthText.style.color = '#ef4444';
                } else if (strength < 100) {
                    strengthBar.style.backgroundColor = '#f59e0b';
                    strengthText.textContent = 'Medium';
                    strengthText.style.color = '#f59e0b';
                } else {
                    strengthBar.style.backgroundColor = '#10b981';
                    strengthText.textContent = 'Strong';
                    strengthText.style.color = '#10b981';
                }
            });
        }

        changePasswordForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const currentPassword = document.getElementById('current-password').value;
            const newPassword = newPasswordInput.value;
            const confirmPassword = confirmPasswordInput.value;

            // Check if passwords match
            if (newPassword !== confirmPassword) {
                showFlash('New passwords do not match', 'error');
                return;
            }

            // Check if new password is same as current
            if (currentPassword === newPassword) {
                showFlash('New password must be different from current password', 'error');
                return;
            }

            // Client-side password validation
            const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{14,}$/;
            if (!passwordRegex.test(newPassword)) {
                showFlash('Password must be at least 14 characters and contain uppercase, lowercase, number, and special character', 'error');
                return;
            }

            const formData = {
                current_password: currentPassword,
                new_password: newPassword
            };

            try {
                const result = await API.request('/api/v1/user/change-password', {
                    method: 'POST',
                    body: JSON.stringify(formData)
                });

                showFlash(result.message || 'Password changed successfully! Redirecting to login...', 'success');
                changePasswordForm.reset();
                strengthIndicator.style.display = 'none';

                // Redirect to login after 2 seconds
                setTimeout(() => {
                    window.location.href = '/logout';
                }, 2000);
            } catch (error) {
                showFlash('Failed to change password: ' + error.message, 'error');
            }
        });
    }

    // Change Email Form
    const changeEmailForm = document.getElementById('change-email-form');
    if (changeEmailForm) {
        changeEmailForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const newEmail = document.getElementById('new-email').value.trim();
            const password = document.getElementById('email-change-password').value;

            // Client-side validation
            if (!newEmail || !password) {
                showFlash('All fields are required', 'error');
                return;
            }

            // Basic email format validation
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(newEmail)) {
                showFlash('Please enter a valid email address', 'error');
                return;
            }

            // Confirm action
            if (!confirm('Are you sure you want to change your email? You will be logged out and need to verify your new email.')) {
                return;
            }

            try {
                const result = await API.changeEmail({
                    new_email: newEmail,
                    password: password
                });

                showFlash(result.message || 'Email changed successfully! Please check your new email for verification.', 'success');
                changeEmailForm.reset();

                // Redirect to login after 3 seconds
                setTimeout(() => {
                    window.location.href = '/logout';
                }, 3000);
            } catch (error) {
                showFlash('Failed to change email: ' + error.message, 'error');
            }
        });
    }

    // Create Note Form
    const createNoteForm = document.getElementById('create-note-form');
    if (createNoteForm) {
        createNoteForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const formData = {
                title: document.getElementById('note-title').value,
                content: document.getElementById('note-content').value
            };

            try {
                const result = await API.createNote(formData);
                showFlash('Note created successfully!', 'success');
                createNoteForm.reset();

                // Close modal using helper function
                closeModal('note-modal-overlay');

                // Refresh drive
                cache.lastFetch.notes = 0;
                await renderDrive();
            } catch (error) {
                showFlash('Failed to create note: ' + error.message, 'error');
            }
        });
    }

    // Create Folder Form
    const createFolderForm = document.getElementById('create-folder-form');
    if (createFolderForm) {
        createFolderForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const formData = {
                name: document.getElementById('folder-name').value,
                parent_folder_id: null, // Add support for nested folders if needed
                team_id: currentTeamId // Use current team context
            };

            try {
                const result = await API.request('/api/v1/drive/folders', {
                    method: 'POST',
                    body: JSON.stringify(formData)
                });
                showFlash('Folder created successfully!', 'success');
                createFolderForm.reset();

                // Close modal using helper function
                closeModal('folder-modal-overlay');

                // Refresh drive with team context
                await renderDrive(currentTeamId);
            } catch (error) {
                showFlash('Failed to create folder: ' + error.message, 'error');
            }
        });
    }

    // File Upload Handler
    const uploadFileBtn = document.getElementById('upload-file-btn');
    if (uploadFileBtn) {
        uploadFileBtn.addEventListener('click', () => {
            const fileInput = document.createElement('input');
            fileInput.type = 'file';
            fileInput.accept = '.jpg,.jpeg,.png,.txt,.pdf,.docx,.csv';
            fileInput.onchange = async (e) => {
                const file = e.target.files[0];
                if (!file) return;

                const formData = new FormData();
                formData.append('file', file);

                // Add team_id if in team context
                if (currentTeamId) {
                    formData.append('team_id', currentTeamId.toString());
                }

                try {
                    const result = await API.uploadFile(formData);
                    showFlash('File uploaded successfully!', 'success');

                    // Refresh drive with team context
                    cache.lastFetch.notes = 0;
                    await renderDrive(currentTeamId);
                } catch (error) {
                    showFlash('Failed to upload file: ' + error.message, 'error');
                }
            };
            fileInput.click();
        });
    }

    // Upload to Folder Handler
    const uploadToFolderBtn = document.getElementById('upload-to-folder-btn');
    if (uploadToFolderBtn) {
        uploadToFolderBtn.addEventListener('click', () => {
            if (!currentFolderId) {
                showFlash('No folder selected', 'error');
                return;
            }

            const fileInput = document.createElement('input');
            fileInput.type = 'file';
            fileInput.accept = '.jpg,.jpeg,.png,.txt,.pdf,.docx,.csv';
            fileInput.onchange = async (e) => {
                const file = e.target.files[0];
                if (!file) return;

                const formData = new FormData();
                formData.append('file', file);
                formData.append('folder_id', currentFolderId.toString());

                // Add team_id if in team context
                if (currentTeamId) {
                    formData.append('team_id', currentTeamId.toString());
                }

                try {
                    showFlash('Uploading file...', 'info', 2000);
                    const result = await API.uploadFile(formData);
                    showFlash('File uploaded to folder successfully!', 'success');

                    // Refresh the folder contents
                    const response = await API.request(`/api/v1/drive/folders/${currentFolderId}/contents`);
                    const contents = response.contents || [];

                    const contentsGrid = document.getElementById('folder-contents-grid');
                    if (contents.length === 0) {
                        contentsGrid.innerHTML = '<p>This folder is empty</p>';
                    } else {
                        const items = contents.map(item => {
                            const icon = item.type === 'folder' ? '📁' :
                                        item.type === 'note' ? '📝' : '📄';
                            const sizeInfo = item.size ? `<div class="file-item-meta">${(item.size / 1024).toFixed(1)} KB</div>` : '';
                            const createdDate = item.created_at ? new Date(item.created_at).toLocaleDateString() : '';

                            return `
                                <div class="file-item card">
                                    <div class="file-item-icon">${icon}</div>
                                    <div class="file-item-name">${item.name}</div>
                                    ${sizeInfo}
                                    <div class="file-item-meta">${createdDate}</div>
                                </div>
                            `;
                        }).join('');

                        contentsGrid.innerHTML = items;
                    }

                    // Also refresh the main drive view
                    cache.lastFetch.notes = 0;
                    await renderDrive();
                } catch (error) {
                    showFlash('Failed to upload file: ' + error.message, 'error');
                }
            };
            fileInput.click();
        });
    }

    // ===== MODAL HANDLERS =====
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                overlay.classList.remove('active');
                overlay.querySelector('.modal').classList.remove('active');
            }
        });
    });

    // Close button handlers
    document.querySelectorAll('.close-modal-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const overlay = btn.closest('.modal-overlay');
            if (overlay) {
                closeModal(overlay.id);
            }
        });
    });

    // ===== TEAM ASSIGNMENT MODAL HANDLERS =====
    const confirmAssignTeamBtn = document.getElementById('confirm-assign-team-btn');
    const cancelAssignTeamBtn = document.getElementById('cancel-assign-team-btn');

    if (confirmAssignTeamBtn) {
        confirmAssignTeamBtn.addEventListener('click', async () => {
            const teamSelect = document.getElementById('assign-team-select');
            const teamId = parseInt(teamSelect.value);
            const ideaId = confirmAssignTeamBtn.dataset.ideaId;
            const errorMsg = document.getElementById('assign-team-error');
            const successMsg = document.getElementById('assign-team-success');

            if (!teamId || teamId === 0) {
                errorMsg.textContent = 'Please select a team';
                errorMsg.style.display = 'block';
                return;
            }

            try {
                confirmAssignTeamBtn.disabled = true;
                confirmAssignTeamBtn.textContent = 'Assigning...';

                // Call API to assign idea to team
                const response = await fetch(`/api/v1/ideas/idea/${ideaId}/assign-team`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': API.getCSRFToken()
                    },
                    credentials: 'same-origin',
                    body: JSON.stringify({ team_id: teamId })
                });

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.detail || 'Failed to assign idea to team');
                }

                // Show success message
                successMsg.textContent = 'Idea successfully assigned to team!';
                successMsg.style.display = 'block';
                errorMsg.style.display = 'none';

                // Refresh ideas list
                cache.lastFetch.ideas = 0;
                await renderAllIdeas();

                // Close modal after short delay
                setTimeout(() => {
                    closeModal('assign-team-modal-overlay');
                    successMsg.style.display = 'none';
                }, 1500);

            } catch (error) {
                errorMsg.textContent = error.message;
                errorMsg.style.display = 'block';
                successMsg.style.display = 'none';
            } finally {
                confirmAssignTeamBtn.disabled = false;
                confirmAssignTeamBtn.textContent = 'Assign to Team';
            }
        });
    }

    if (cancelAssignTeamBtn) {
        cancelAssignTeamBtn.addEventListener('click', () => {
            closeModal('assign-team-modal-overlay');
        });
    }

    // ===== DELETE CONFIRMATION MODAL HANDLERS =====
    const deleteConfirmCheckbox = document.getElementById('confirm-delete-checkbox');
    const confirmDeleteIdeaBtn = document.getElementById('confirm-delete-idea-btn');
    const cancelDeleteIdeaBtn = document.getElementById('cancel-delete-idea-btn');

    // Enable/disable delete button based on checkbox
    if (deleteConfirmCheckbox && confirmDeleteIdeaBtn) {
        deleteConfirmCheckbox.addEventListener('change', () => {
            confirmDeleteIdeaBtn.disabled = !deleteConfirmCheckbox.checked;
        });
    }

    if (confirmDeleteIdeaBtn) {
        confirmDeleteIdeaBtn.addEventListener('click', async () => {
            const ideaId = confirmDeleteIdeaBtn.dataset.ideaId;
            const contentType = confirmDeleteIdeaBtn.dataset.contentType || 'text';
            const errorMsg = document.getElementById('delete-idea-error');

            try {
                confirmDeleteIdeaBtn.disabled = true;
                confirmDeleteIdeaBtn.textContent = 'Deleting...';

                // Call appropriate API endpoint based on content type
                const endpoint = contentType === 'image'
                    ? `/api/v1/ideas/image/${ideaId}`
                    : `/api/v1/ideas/idea/${ideaId}`;

                console.log(`🗑️ Deleting ${contentType} with ID ${ideaId} at endpoint: ${endpoint}`);

                const response = await fetch(endpoint, {
                    method: 'DELETE',
                    headers: {
                        'X-CSRF-Token': API.getCSRFToken()
                    },
                    credentials: 'same-origin'
                });

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.detail || `Failed to delete ${contentType}`);
                }

                // Show success flash message
                const successMessage = contentType === 'image' ? 'Image deleted successfully' : 'Idea deleted successfully';
                showFlash(successMessage, 'success');

                // Close modal
                closeModal('delete-idea-modal-overlay');

                // Reset checkbox
                if (deleteConfirmCheckbox) {
                    deleteConfirmCheckbox.checked = false;
                }

                // Refresh ideas list
                cache.lastFetch.ideas = 0;
                await renderAllIdeas();

            } catch (error) {
                errorMsg.textContent = error.message;
                errorMsg.style.display = 'block';
                confirmDeleteIdeaBtn.disabled = false;
                confirmDeleteIdeaBtn.textContent = 'Delete Permanently';
            }
        });
    }

    if (cancelDeleteIdeaBtn) {
        cancelDeleteIdeaBtn.addEventListener('click', () => {
            closeModal('delete-idea-modal-overlay');
            // Reset checkbox when canceling
            if (deleteConfirmCheckbox) {
                deleteConfirmCheckbox.checked = false;
            }
        });
    }

    // Open modals
    const composeMessageBtn = document.getElementById('compose-message-btn');
    if (composeMessageBtn) {
        composeMessageBtn.addEventListener('click', () => {
            document.getElementById('compose-message-modal-overlay').classList.add('active');
            document.getElementById('compose-message-modal').classList.add('active');
        });
    }

    const createNoteBtn = document.getElementById('create-note-btn');
    console.log('Create Note Button:', createNoteBtn);
    if (createNoteBtn) {
        createNoteBtn.addEventListener('click', () => {
            console.log('Create Note button clicked');
            const overlay = document.getElementById('note-modal-overlay');
            const modal = document.getElementById('note-modal');
            console.log('Note modal overlay:', overlay);
            console.log('Note modal:', modal);

            // Add class and force ALL styles
            overlay.classList.add('active');
            modal.classList.add('active');
            overlay.style.display = 'grid';
            overlay.style.opacity = '1';
            overlay.style.zIndex = '9999';
            modal.style.display = 'flex';
            modal.style.opacity = '1';
            modal.style.transform = 'scale(1)';

            console.log('Active classes added - overlay has active:', overlay.classList.contains('active'));
            console.log('Overlay computed display:', window.getComputedStyle(overlay).display);
            console.log('Overlay computed opacity:', window.getComputedStyle(overlay).opacity);
            console.log('Overlay computed z-index:', window.getComputedStyle(overlay).zIndex);
            console.log('Modal computed display:', window.getComputedStyle(modal).display);
            console.log('Modal computed opacity:', window.getComputedStyle(modal).opacity);
        });
    }

    const createFolderBtn = document.getElementById('create-folder-btn');
    console.log('Create Folder Button:', createFolderBtn);
    if (createFolderBtn) {
        createFolderBtn.addEventListener('click', () => {
            console.log('Create Folder button clicked');
            const overlay = document.getElementById('folder-modal-overlay');
            const modal = document.getElementById('folder-modal');
            console.log('Folder modal overlay:', overlay);
            console.log('Folder modal:', modal);

            // Add class and force ALL styles
            overlay.classList.add('active');
            modal.classList.add('active');
            overlay.style.display = 'grid';
            overlay.style.opacity = '1';
            overlay.style.zIndex = '9999';
            modal.style.display = 'flex';
            modal.style.opacity = '1';
            modal.style.transform = 'scale(1)';

            console.log('Active classes added - overlay has active:', overlay.classList.contains('active'));
            console.log('Overlay computed display:', window.getComputedStyle(overlay).display);
            console.log('Overlay computed opacity:', window.getComputedStyle(overlay).opacity);
            console.log('Overlay computed z-index:', window.getComputedStyle(overlay).zIndex);
            console.log('Modal computed display:', window.getComputedStyle(modal).display);
            console.log('Modal computed opacity:', window.getComputedStyle(modal).opacity);
        });
    }

    // Dashboard "Create New Idea" button
    const dashboardCreateBtn = document.getElementById('dashboard-create-new-btn');
    if (dashboardCreateBtn) {
        dashboardCreateBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            await showPage('create-idea-page');
        });
    }

    // ===== SHARE TO TEAM FUNCTIONALITY =====

    // Function to fetch and populate teams dropdown
    async function populateTeamsDropdown() {
        const teamSelect = document.getElementById('share-team-select');

        try {
            const data = await API.request('/api/v1/drive/teams');
            const teams = data.teams || [];

            // Clear existing options (except first)
            teamSelect.innerHTML = '<option value="">Choose a team...</option>';

            if (teams && teams.length > 0) {
                teams.forEach(team => {
                    const option = document.createElement('option');
                    option.value = team.id;
                    option.textContent = team.name;
                    teamSelect.appendChild(option);
                });
            } else {
                const option = document.createElement('option');
                option.value = '';
                option.textContent = 'No teams available - Create a team first';
                option.disabled = true;
                teamSelect.appendChild(option);
            }
        } catch (error) {
            console.error('Failed to load teams:', error);
            showFlash('Failed to load teams', 'error');
        }
    }

    // Share modal close handlers
    document.getElementById('close-share-modal')?.addEventListener('click', () => {
        const overlay = document.getElementById('share-modal-overlay');
        const modal = document.getElementById('share-modal');
        overlay.classList.remove('active');
        modal.classList.remove('active');
        document.getElementById('share-message').value = '';
    });

    document.getElementById('cancel-share-btn')?.addEventListener('click', () => {
        const overlay = document.getElementById('share-modal-overlay');
        const modal = document.getElementById('share-modal');
        overlay.classList.remove('active');
        modal.classList.remove('active');
        document.getElementById('share-message').value = '';
    });

    // Share modal confirm handler
    document.getElementById('confirm-share-btn')?.addEventListener('click', async () => {
        const teamId = document.getElementById('share-team-select').value;
        const permission = document.getElementById('share-permission').value;
        const message = document.getElementById('share-message').value;

        if (!teamId) {
            showFlash('Please select a team', 'error');
            return;
        }

        if (!window.currentShareItem) {
            showFlash('No item selected', 'error');
            return;
        }

        const { id, type, name } = window.currentShareItem;

        try {
            const shareData = {
                item_id: id,
                item_type: type,
                team_id: parseInt(teamId),
                permission: permission,
                message: message || null
            };

            await API.request('/api/v1/drive/share', {
                method: 'POST',
                body: JSON.stringify(shareData)
            });

            showFlash(`Successfully shared "${name}" with team!`, 'success');

            const overlay = document.getElementById('share-modal-overlay');
            const modal = document.getElementById('share-modal');
            overlay.classList.remove('active');
            modal.classList.remove('active');
            document.getElementById('share-message').value = '';

            // Refresh drive to show updated items
            await renderDrive();
        } catch (error) {
            console.error('Share error:', error);
            showFlash('Failed to share item: ' + error.message, 'error');
        }
    });

    // ===== DISPLAY GENERATED IMAGE =====
    window.displayGeneratedImage = function(image) {
        // Create a modal to display the generated image
        const modal = document.createElement('div');
        modal.className = 'modal-overlay active';
        modal.innerHTML = `
            <div class="modal active" style="max-width: 800px;">
                <div class="modal-header">
                    <h2>Generated Image</h2>
                    <button class="modal-close">&times;</button>
                </div>
                <div class="modal-body" style="text-align: center;">
                    <img src="${image.image_url}" alt="Generated Image" style="max-width: 100%; border-radius: 8px; margin-bottom: 1rem;">
                    <div style="text-align: left; background: #1a1a1a; padding: 1rem; border-radius: 8px; margin-top: 1rem;">
                        <p style="margin: 0.5rem 0;"><strong>Prompt:</strong> ${image.prompt}</p>
                        <p style="margin: 0.5rem 0;"><strong>Style:</strong> ${image.style || 'Realistic'}</p>
                        <p style="margin: 0.5rem 0;"><strong>Aspect Ratio:</strong> ${image.aspect_ratio}</p>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="this.closest('.modal-overlay').remove()">Close</button>
                    <a href="${image.image_url}" download="generated-image.png" class="btn btn-primary">Download</a>
                </div>
            </div>
        `;

        // Add close functionality
        const closeBtn = modal.querySelector('.modal-close');
        closeBtn.addEventListener('click', () => modal.remove());

        // Close on overlay click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.remove();
            }
        });

        document.body.appendChild(modal);
    };

    // ===== MESSAGES INITIALIZATION =====
    // Initialize messages functionality if available
    if (typeof window.initializeMessages === 'function') {
        window.initializeMessages();
    }

    // ===== INITIAL PAGE LOAD =====
    await renderDashboard();
});
