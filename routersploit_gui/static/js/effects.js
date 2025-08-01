// RouterSploit GUI - Visual Effects and Sound System

class EffectsManager {
    constructor() {
        this.soundEnabled = true;
        this.matrixRain = null;
        this.particles = [];
        this.sounds = {};
        this.init();
    }

    init() {
        this.loadSounds();
        this.initMatrixRain();
        this.initParticles();
        this.initEventListeners();
        this.startupSequence();
    }

    // Sound System
    loadSounds() {
        const soundTypes = ['click', 'type', 'success', 'error', 'startup', 'scan'];
        soundTypes.forEach(type => {
            this.sounds[type] = document.getElementById(`sound${type.charAt(0).toUpperCase() + type.slice(1)}`);
            if (this.sounds[type]) {
                this.sounds[type].volume = 0.3;
            }
        });
    }

    playSound(type) {
        if (this.soundEnabled && this.sounds[type]) {
            this.sounds[type].currentTime = 0;
            this.sounds[type].play().catch(e => console.log('Sound play failed:', e));
        }
    }

    toggleSound() {
        this.soundEnabled = !this.soundEnabled;
        const soundToggle = document.getElementById('soundToggle');
        const icon = soundToggle.querySelector('i');
        
        if (this.soundEnabled) {
            icon.className = 'fas fa-volume-up';
            soundToggle.title = 'Disable Sound';
            this.playSound('click');
        } else {
            icon.className = 'fas fa-volume-mute';
            soundToggle.title = 'Enable Sound';
        }
    }

    // Matrix Rain Effect
    initMatrixRain() {
        const matrixContainer = document.getElementById('matrixRain');
        if (!matrixContainer) return;

        this.matrixRain = {
            container: matrixContainer,
            columns: Math.floor(window.innerWidth / 20),
            drops: []
        };

        // Initialize drops
        for (let i = 0; i < this.matrixRain.columns; i++) {
            this.matrixRain.drops.push(Math.random() * window.innerHeight);
        }

        this.createMatrixColumns();
        this.startMatrixRain();
    }

    createMatrixColumns() {
        const chars = '0123456789ABCDEF!@#$%^&*()_+-=[]{}|;:,.<>?';
        
        for (let i = 0; i < this.matrixRain.columns; i++) {
            const column = document.createElement('div');
            column.className = 'matrix-column';
            column.style.left = `${i * 20}px`;
            column.style.animationDuration = `${Math.random() * 3 + 2}s`;
            column.style.animationDelay = `${Math.random() * 2}s`;
            
            // Generate random characters
            let text = '';
            for (let j = 0; j < 30; j++) {
                text += chars[Math.floor(Math.random() * chars.length)] + '<br>';
            }
            column.innerHTML = text;
            
            this.matrixRain.container.appendChild(column);
        }
    }

    startMatrixRain() {
        // Matrix rain is now handled by CSS animations
        // This method can be used for additional logic if needed
    }

    // Particle System
    initParticles() {
        const particlesContainer = document.getElementById('particles');
        if (!particlesContainer) return;

        this.createParticles(particlesContainer);
        setInterval(() => this.createParticles(particlesContainer), 500);
    }

    createParticles(container) {
        for (let i = 0; i < 3; i++) {
            const particle = document.createElement('div');
            particle.className = 'particle';
            particle.style.left = `${Math.random() * 100}%`;
            particle.style.animationDuration = `${Math.random() * 3 + 2}s`;
            particle.style.animationDelay = `${Math.random() * 2}s`;
            
            container.appendChild(particle);
            
            // Remove particle after animation
            setTimeout(() => {
                if (particle.parentNode) {
                    particle.parentNode.removeChild(particle);
                }
            }, 5000);
        }
    }

    // Event Listeners
    initEventListeners() {
        // Sound toggle
        document.getElementById('soundToggle')?.addEventListener('click', () => {
            this.toggleSound();
        });

        // Theme toggle and Fullscreen toggle are handled by app.js to avoid conflicts
        // Removed duplicate handlers to prevent event conflicts

        // Add click sounds to all buttons
        document.querySelectorAll('.btn').forEach(btn => {
            btn.addEventListener('click', () => this.playSound('click'));
        });

        // Add typing sounds to input fields
        document.querySelectorAll('input[type="text"], textarea').forEach(input => {
            input.addEventListener('input', () => this.playSound('type'));
        });

        // Window resize handler
        window.addEventListener('resize', () => {
            this.handleResize();
        });
    }

    // Theme Toggle and Fullscreen Toggle functions moved to app.js to avoid conflicts
    // These functions are no longer used here to prevent duplicate event handlers

    // Window Resize Handler
    handleResize() {
        // Recreate matrix rain for new window size
        if (this.matrixRain) {
            this.matrixRain.container.innerHTML = '';
            this.matrixRain.columns = Math.floor(window.innerWidth / 20);
            this.matrixRain.drops = [];
            
            for (let i = 0; i < this.matrixRain.columns; i++) {
                this.matrixRain.drops.push(Math.random() * window.innerHeight);
            }
            
            this.createMatrixColumns();
        }
    }

    // Startup Sequence
    startupSequence() {
        this.playSound('startup');
        
        // Animate title
        const title = document.querySelector('.navbar-brand');
        if (title) {
            title.style.opacity = '0';
            setTimeout(() => {
                title.style.transition = 'opacity 2s ease-in-out';
                title.style.opacity = '1';
            }, 500);
        }

        // Animate cards
        const cards = document.querySelectorAll('.card');
        cards.forEach((card, index) => {
            card.style.transform = 'translateY(50px)';
            card.style.opacity = '0';
            setTimeout(() => {
                card.style.transition = 'transform 0.5s ease-out, opacity 0.5s ease-out';
                card.style.transform = 'translateY(0)';
                card.style.opacity = '1';
            }, 800 + index * 200);
        });

        // Initialize status
        this.updateStatus('System Online', 'success');
    }

    // Status Updates
    updateStatus(message, type = 'info') {
        const statusBadge = document.getElementById('statusBadge');
        if (!statusBadge) return;

        const icon = statusBadge.querySelector('i');
        const text = statusBadge.querySelector('.typing-effect') || statusBadge.querySelector('span');
        
        // Update classes
        statusBadge.className = `badge bg-${type} holographic`;
        
        // Update text with typing effect
        if (text) {
            this.typeText(text, message);
        }

        // Play appropriate sound
        if (type === 'success') {
            this.playSound('success');
        } else if (type === 'danger') {
            this.playSound('error');
        } else {
            this.playSound('click');
        }
    }

    // Typing Effect
    typeText(element, text, speed = 50) {
        element.textContent = '';
        let i = 0;
        
        const typeChar = () => {
            if (i < text.length) {
                element.textContent += text.charAt(i);
                i++;
                setTimeout(typeChar, speed);
            }
        };
        
        typeChar();
    }

    // Glitch Effect
    glitchText(element, originalText) {
        const glitchChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';
        let glitchText = '';
        
        for (let i = 0; i < originalText.length; i++) {
            if (Math.random() < 0.1) {
                glitchText += glitchChars[Math.floor(Math.random() * glitchChars.length)];
            } else {
                glitchText += originalText[i];
            }
        }
        
        element.textContent = glitchText;
        
        setTimeout(() => {
            element.textContent = originalText;
        }, 100);
    }

    // Scanning Animation
    startScanning(element) {
        const scanLine = document.getElementById('scanningLine');
        if (scanLine) {
            scanLine.style.display = 'block';
            this.playSound('scan');
            
            setTimeout(() => {
                scanLine.style.display = 'none';
            }, 2000);
        }
    }

    // Loading Overlay
    showLoading(message = 'Processing...') {
        const overlay = document.getElementById('loadingOverlay');
        const messageElement = overlay.querySelector('p');
        
        if (messageElement) {
            this.typeText(messageElement, message);
        }
        
        overlay.style.display = 'flex';
        this.playSound('scan');
    }

    hideLoading() {
        const overlay = document.getElementById('loadingOverlay');
        overlay.style.display = 'none';
    }

    // Console Effects
    addConsoleOutput(text, type = 'info') {
        const consoleOutputs = ['outputContainer', 'consoleOutput', 'autoOwnOutput'];
        
        consoleOutputs.forEach(containerId => {
            const container = document.getElementById(containerId);
            if (container) {
                const line = document.createElement('div');
                line.className = `console-line ${type}`;
                line.innerHTML = text;
                container.appendChild(line);
                
                // Auto-scroll to bottom
                container.scrollTop = container.scrollHeight;
                
                // Add typing effect for new lines
                if (type === 'info') {
                    this.playSound('type');
                } else if (type === 'success') {
                    this.playSound('success');
                } else if (type === 'error') {
                    this.playSound('error');
                }
            }
        });
    }

    // Button Enhancement
    enhanceButtons() {
        document.querySelectorAll('.btn').forEach(btn => {
            btn.addEventListener('mouseenter', () => {
                btn.style.transform = 'translateY(-2px)';
            });
            
            btn.addEventListener('mouseleave', () => {
                btn.style.transform = 'translateY(0)';
            });
        });
    }

    // Module Tree Enhancement
    enhanceModuleTree() {
        const moduleTree = document.getElementById('moduleTree');
        if (!moduleTree) return;

        // Add hover effects
        moduleTree.addEventListener('mouseover', (e) => {
            if (e.target.classList.contains('tree-node')) {
                this.glitchText(e.target, e.target.textContent);
            }
        });

        // Add search functionality
        const searchInput = document.getElementById('moduleSearch');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.filterModules(e.target.value);
            });
        }
    }

    filterModules(searchTerm) {
        const modules = document.querySelectorAll('.tree-node.module');
        modules.forEach(module => {
            const text = module.textContent.toLowerCase();
            if (text.includes(searchTerm.toLowerCase())) {
                module.style.display = 'block';
            } else {
                module.style.display = 'none';
            }
        });
    }

    // Progressive Web App Features
    initPWA() {
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/sw.js').catch(e => {
                console.log('Service worker registration failed:', e);
            });
        }
    }

    // Performance Monitoring
    monitorPerformance() {
        const observer = new PerformanceObserver((list) => {
            list.getEntries().forEach((entry) => {
                if (entry.duration > 100) {
                    console.warn('Slow operation detected:', entry.name, entry.duration);
                }
            });
        });
        
        observer.observe({ entryTypes: ['measure'] });
    }
}

// Initialize Effects Manager
let effectsManager;

document.addEventListener('DOMContentLoaded', () => {
    effectsManager = new EffectsManager();
    effectsManager.enhanceButtons();
    effectsManager.enhanceModuleTree();
    effectsManager.initPWA();
    effectsManager.monitorPerformance();
});

// Export for use in other scripts
window.effectsManager = effectsManager; 