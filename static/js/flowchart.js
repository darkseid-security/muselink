/**
 * Flowchart Generator for Genesis AI Platform
 * Creates interactive flowcharts using Mermaid.js
 */

class FlowchartGenerator {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.mermaidInitialized = false;
        this.loadMermaid();
    }

    loadMermaid() {
        if (typeof mermaid === 'undefined') {
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js';
            script.onload = () => {
                mermaid.initialize({
                    startOnLoad: false,
                    theme: 'default',
                    securityLevel: 'strict',  // SECURITY: Prevents XSS - disallows click events and script tags
                    flowchart: {
                        useMaxWidth: true,
                        htmlLabels: false,  // SECURITY: Disable HTML in labels to prevent XSS
                        curve: 'basis'
                    }
                });
                this.mermaidInitialized = true;
            };
            document.head.appendChild(script);
        } else {
            this.mermaidInitialized = true;
        }
    }

    async render(mermaidCode) {
        if (!this.mermaidInitialized) {
            await new Promise(resolve => setTimeout(resolve, 500));
            return this.render(mermaidCode);
        }

        try {
            const { svg } = await mermaid.render('flowchart-' + Date.now(), mermaidCode);
            this.container.innerHTML = svg;
        } catch (error) {
            console.error('Flowchart render error:', error);
            this.container.innerHTML = `<div class="error">Failed to render flowchart: ${error.message}</div>`;
        }
    }

    // Predefined creative project templates
    templates = {
        storyboard: `
            flowchart LR
                A[Scene 1: Opening] --> B[Scene 2: Conflict]
                B --> C[Scene 3: Rising Action]
                C --> D[Scene 4: Climax]
                D --> E[Scene 5: Resolution]
                E --> F[Scene 6: Conclusion]

                A -.-> G[Visual: Wide shot]
                B -.-> H[Visual: Close-up]
                C -.-> I[Visual: Action sequence]
                D -.-> J[Visual: Dramatic moment]
                E -.-> K[Visual: Calm after storm]
                F -.-> L[Visual: Final shot]
        `,

        productRoadmap: `
            flowchart TD
                A[Product Concept] --> B[Market Research]
                B --> C{Viable?}
                C -->|No| D[Refine Concept]
                D --> B
                C -->|Yes| E[Create MVP]
                E --> F[User Testing]
                F --> G{Feedback Good?}
                G -->|No| H[Iterate Features]
                H --> F
                G -->|Yes| I[Beta Launch]
                I --> J[Gather Analytics]
                J --> K[Scale Marketing]
                K --> L[Full Release]
                L --> M[Monitor & Improve]
        `,

        creativeWorkflow: `
            flowchart TD
                A[Creative Brief] --> B[AI Draft Generation]
                B --> C[Review Generated Drafts]
                C --> D{Select Draft}
                D --> E[Edit & Refine]
                E --> F[Add Personal Touch]
                F --> G{Stakeholder Review}
                G -->|Revisions| H[Incorporate Feedback]
                H --> E
                G -->|Approved| I[Finalize Assets]
                I --> J[Export & Deliver]
                J --> K[Archive Project]
        `,

        videoProduction: `
            flowchart TD
                A[Concept Development] --> B[Script Writing]
                B --> C[Storyboarding]
                C --> D[Shot List Planning]
                D --> E[Pre-Production]
                E --> F[Filming Day 1]
                F --> G[Filming Day 2]
                G --> H[Review Footage]
                H --> I{Reshoot Needed?}
                I -->|Yes| J[Additional Filming]
                J --> H
                I -->|No| K[Video Editing]
                K --> L[Color Grading]
                L --> M[Sound Design]
                M --> N[Final Review]
                N --> O[Export & Publish]
        `,

        contentPipeline: `
            flowchart TD
                A[Content Idea] --> B[AI Research & Drafting]
                B --> C[Content Creation]
                C --> D[Visual Assets]
                D --> E[SEO Optimization]
                E --> F{Quality Check}
                F -->|Fail| G[Revise Content]
                G --> C
                F -->|Pass| H[Schedule Publishing]
                H --> I[Publish Content]
                I --> J[Promote on Social]
                J --> K[Monitor Performance]
                K --> L[Analyze Metrics]
                L --> M[Optimize Strategy]
        `,

        marketingCampaign: `
            flowchart TD
                A[Campaign Goals] --> B[Target Audience Research]
                B --> C[AI-Generate Ideas]
                C --> D[Select Campaign Concept]
                D --> E[Create Assets]
                E --> F[Design Landing Page]
                F --> G[Setup Email Automation]
                G --> H[Launch Campaign]
                H --> I[Monitor KPIs]
                I --> J{Goals Met?}
                J -->|No| K[A/B Test Variations]
                K --> I
                J -->|Yes| L[Scale Budget]
                L --> M[Expand Channels]
                M --> N[Final Report]
        `,

        characterDev: `
            flowchart TD
                A[Character Concept] --> B[Backstory Development]
                B --> C[Personality Traits]
                C --> D[Visual Design]
                D --> E[Character Arc]
                E --> F[Relationships & Conflicts]
                F --> G[Dialogue Voice]
                G --> H[Character Testing]
                H --> I{Resonates?}
                I -->|No| J[Refine Character]
                J --> C
                I -->|Yes| K[Integrate into Story]
                K --> L[Character Evolution]
                L --> M[Final Character Profile]
        `
    };

    renderTemplate(templateName) {
        if (this.templates[templateName]) {
            this.render(this.templates[templateName]);
        } else {
            console.error('Template not found:', templateName);
        }
    }

    // Generate flowchart from JSON structure
    generateFromJSON(data) {
        let mermaidCode = 'flowchart TD\n';
        
        const processNode = (node, parentId = null) => {
            const nodeId = node.id || `node_${Math.random().toString(36).substr(2, 9)}`;
            const label = node.label || 'Unnamed';
            const shape = node.shape || 'rect'; // rect, round, diamond, circle
            
            let nodeCode = '';
            switch (shape) {
                case 'round':
                    nodeCode = `${nodeId}(${label})`;
                    break;
                case 'diamond':
                    nodeCode = `${nodeId}{${label}}`;
                    break;
                case 'circle':
                    nodeCode = `${nodeId}((${label}))`;
                    break;
                default:
                    nodeCode = `${nodeId}[${label}]`;
            }
            
            if (parentId) {
                const edgeLabel = node.edgeLabel || '';
                mermaidCode += `    ${parentId} -->|${edgeLabel}| ${nodeCode}\n`;
            } else {
                mermaidCode += `    ${nodeCode}\n`;
            }
            
            if (node.children && node.children.length > 0) {
                node.children.forEach(child => {
                    processNode(child, nodeId);
                });
            }
        };
        
        if (Array.isArray(data)) {
            data.forEach(node => processNode(node));
        } else {
            processNode(data);
        }
        
        this.render(mermaidCode);
    }

    // Export flowchart as image
    async exportAsImage(format = 'png') {
        const svg = this.container.querySelector('svg');
        if (!svg) {
            throw new Error('No flowchart to export');
        }

        const svgData = new XMLSerializer().serializeToString(svg);
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        const img = new Image();

        // High-resolution export: 8x scale for ultra-crisp images (print quality)
        const SCALE_FACTOR = 8;

        return new Promise((resolve, reject) => {
            img.onload = () => {
                // Scale canvas to 8x resolution for ultra-high quality export
                canvas.width = img.width * SCALE_FACTOR;
                canvas.height = img.height * SCALE_FACTOR;

                // Enable image smoothing for better quality
                ctx.imageSmoothingEnabled = true;
                ctx.imageSmoothingQuality = 'high';

                // Scale the context to match
                ctx.scale(SCALE_FACTOR, SCALE_FACTOR);

                // Draw the image at the scaled size
                ctx.drawImage(img, 0, 0);

                // Export as PNG with high quality
                canvas.toBlob(blob => {
                    resolve(blob);
                }, `image/${format}`, 1.0);  // 1.0 = maximum quality
            };

            img.onerror = reject;
            img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgData)));
        });
    }

    // Download flowchart
    async download(filename = 'flowchart', format = 'png') {
        try {
            const blob = await this.exportAsImage(format);
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${filename}.${format}`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        } catch (error) {
            console.error('Download failed:', error);
        }
    }
}

// Export for use in other scripts
window.FlowchartGenerator = FlowchartGenerator;
