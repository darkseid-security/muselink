document.addEventListener('DOMContentLoaded', () => {

    // ===== HEADER SCROLL EFFECT =====
    const header = document.querySelector('.header');
    if (header) {
        window.addEventListener('scroll', () => {
            header.classList.toggle('scrolled', window.scrollY > 50);
        });
    }

    // ===== RESPONSIVE NAVIGATION =====
    const navToggle = document.getElementById('nav-toggle');
    const mainNav = document.getElementById('main-nav');
    const navLinks = document.querySelectorAll('.nav-link');
    const body = document.body;

    if (navToggle && mainNav) {
        navToggle.addEventListener('click', () => {
            mainNav.classList.toggle('active');
            body.classList.toggle('nav-open');
        });
        navLinks.forEach(link => {
            link.addEventListener('click', () => {
                if (mainNav.classList.contains('active')) {
                    mainNav.classList.remove('active');
                    body.classList.remove('nav-open');
                }
            });
        });
    }

    // ===== FADE-IN ANIMATION ON SCROLL =====
    const scrollElements = document.querySelectorAll('.animate-on-scroll');
    const elementInView = (el, dividend = 1) => {
        const elementTop = el.getBoundingClientRect().top;
        return elementTop <= (window.innerHeight || document.documentElement.clientHeight) / dividend;
    };
    const displayScrollElement = (element) => { element.classList.add('is-visible'); };
    const handleScrollAnimation = () => {
        scrollElements.forEach((el) => {
            if (elementInView(el, 1.25)) { displayScrollElement(el); }
        });
    };
    window.addEventListener('scroll', handleScrollAnimation);
    handleScrollAnimation();

    // ===== INTERACTIVE FEATURES SECTION (Remains same) =====
    const featurePanels = document.querySelectorAll('.feature-panels-content .panel');
    const featureVisual = document.querySelector('.feature-panels-visual');
    if (featurePanels.length > 0 && featureVisual) {
        featurePanels.forEach(panel => { (new Image()).src = panel.dataset.visualUrl; });
        featureVisual.style.backgroundImage = `url(${featurePanels[0].dataset.visualUrl})`;
        featurePanels[0].classList.add('active');
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const currentPanel = entry.target;
                    featureVisual.style.backgroundImage = `url(${currentPanel.dataset.visualUrl})`;
                    featurePanels.forEach(p => p.classList.remove('active'));
                    currentPanel.classList.add('active');
                }
            });
        }, { root: null, rootMargin: '0px', threshold: 0.6 });
        featurePanels.forEach(panel => observer.observe(panel));
    }

    // ===== SECURITY TABS LOGIC =====
    const securityTabs = document.querySelectorAll('.security-tabs .tab');
    const securityPanes = document.querySelectorAll('.security-content-pane');
    if (securityTabs.length > 0) {
        securityTabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const tabNumber = tab.dataset.tab;
                securityTabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                securityPanes.forEach(pane => {
                    if (pane.dataset.pane === tabNumber) {
                        pane.classList.add('active');
                    } else {
                        pane.classList.remove('active');
                    }
                });
            });
        });
    }

    // ===== TESTIMONIAL CARD GLOW EFFECT =====
    const testimonialCards = document.querySelectorAll('.testimonial-card');
    testimonialCards.forEach(card => {
        card.addEventListener('mousemove', e => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            card.style.setProperty('--mouse-x', `${x}px`);
            card.style.setProperty('--mouse-y', `${y}px`);
        });
    });


    // ===== PARTICLE NETWORK FOR HERO VISUAL (Remains same) =====
    const canvas = document.getElementById('particle-canvas');
    if (canvas) {
        const ctx = canvas.getContext('2d');
        const container = document.getElementById('hero-visual');
        let particles = [];
        let animationFrameId;
        const particleCount = 70;
        const connectionDistance = 120;
        const mouseRadius = 100;
        const mouse = { x: null, y: null };
        container.addEventListener('mousemove', (event) => { const rect = canvas.getBoundingClientRect(); mouse.x = event.clientX - rect.left; mouse.y = event.clientY - rect.top; });
        container.addEventListener('mouseleave', () => { mouse.x = null; mouse.y = null; });
        function resizeCanvas() { canvas.width = container.offsetWidth; canvas.height = container.offsetHeight; init(); }
        class Particle { constructor() { this.x = Math.random() * canvas.width; this.y = Math.random() * canvas.height; this.size = Math.random() * 2 + 1; this.speedX = (Math.random() * 1 - 0.5) * 0.5; this.speedY = (Math.random() * 1 - 0.5) * 0.5; const style = getComputedStyle(document.documentElement); this.color = style.getPropertyValue('--accent-start').trim(); } update() { if (this.x > canvas.width || this.x < 0) this.speedX *= -1; if (this.y > canvas.height || this.y < 0) this.speedY *= -1; this.x += this.speedX; this.y += this.speedY; } draw() { ctx.fillStyle = this.color; ctx.beginPath(); ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2); ctx.fill(); } }
        function init() { particles = []; for (let i = 0; i < particleCount; i++) { particles.push(new Particle()); } }
        function connectParticles() { const accentColor = getComputedStyle(document.documentElement).getPropertyValue('--border-color').trim(); for (let a = 0; a < particles.length; a++) { for (let b = a; b < particles.length; b++) { const dx = particles[a].x - particles[b].x; const dy = particles[a].y - particles[b].y; const distance = Math.sqrt(dx * dx + dy * dy); if (distance < connectionDistance) { ctx.strokeStyle = accentColor; ctx.lineWidth = 0.5; ctx.globalAlpha = 1 - (distance / connectionDistance); ctx.beginPath(); ctx.moveTo(particles[a].x, particles[a].y); ctx.lineTo(particles[b].x, particles[b].y); ctx.stroke(); ctx.globalAlpha = 1; } } } }
        function connectToMouse() { if (mouse.x == null || mouse.y == null) return; const accentColor = getComputedStyle(document.documentElement).getPropertyValue('--accent-start').trim(); for(let i = 0; i < particles.length; i++) { const dx = particles[i].x - mouse.x; const dy = particles[i].y - mouse.y; const distance = Math.sqrt(dx * dx + dy * dy); if (distance < mouseRadius) { ctx.strokeStyle = accentColor; ctx.lineWidth = 0.8; ctx.globalAlpha = 1 - (distance / mouseRadius); ctx.beginPath(); ctx.moveTo(particles[i].x, particles[i].y); ctx.lineTo(mouse.x, mouse.y); ctx.stroke(); ctx.globalAlpha = 1; } } }
        function animate() { ctx.clearRect(0, 0, canvas.width, canvas.height); particles.forEach(p => { p.update(); p.draw(); }); connectParticles(); connectToMouse(); animationFrameId = requestAnimationFrame(animate); }
        resizeCanvas();
        animate();
        window.addEventListener('resize', () => { cancelAnimationFrame(animationFrameId); clearTimeout(window.resizeLag); window.resizeLag = setTimeout(() => { resizeCanvas(); animate(); }, 250); });
    }
});